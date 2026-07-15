#!/usr/bin/env python3

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_workflow(name: str) -> dict:
    path = ROOT / ".github/workflows" / name
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(document, dict), f"{name} is not a YAML mapping")
    return document


def step_with(job: dict, key: str, value: str) -> dict:
    for step in job.get("steps", []):
        if step.get(key) == value:
            return step
    raise AssertionError(f"job has no step with {key}={value}")


def shell_commands(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def run_validator(artifact_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(ROOT / "scripts/validate-release-artifacts.sh"),
            "--basic",
            str(artifact_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_release_artifact_rejection() -> None:
    with tempfile.TemporaryDirectory(prefix="ois-quality-policy-") as temporary:
        root = Path(temporary)
        empty = root / "empty"
        empty.mkdir()
        require(run_validator(empty).returncode != 0, "empty artifact set was accepted")

        corrupt = root / "corrupt"
        corrupt.mkdir()
        (corrupt / "corrupt.deb").write_bytes(b"not a Debian package")
        require(run_validator(corrupt).returncode != 0, "corrupt package was accepted")

        package_root = root / "package-root"
        control = package_root / "DEBIAN"
        control.mkdir(parents=True)
        (control / "control").write_text(
            "Package: open-ip-scanner-policy-fixture\n"
            "Version: 1.0\n"
            "Architecture: all\n"
            "Maintainer: Test Fixture <fixture@example.invalid>\n"
            "Description: Quality policy fixture\n",
            encoding="utf-8",
        )
        valid = root / "valid"
        valid.mkdir()
        subprocess.run(
            ["dpkg-deb", "--build", str(package_root), str(valid / "valid.deb")],
            check=True,
            capture_output=True,
            text=True,
        )
        require(run_validator(valid).returncode == 0, "valid package was rejected")

        multiple = root / "multiple"
        multiple.mkdir()
        shutil.copy2(valid / "valid.deb", multiple / "first.deb")
        shutil.copy2(valid / "valid.deb", multiple / "second.deb")
        require(
            run_validator(multiple).returncode != 0,
            "multiple release packages were accepted",
        )


def test_cleanup_preserves_original_failure() -> None:
    with tempfile.TemporaryDirectory(prefix="ois-cleanup-policy-") as temporary:
        root = Path(temporary)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_cmake = fake_bin / "cmake"
        fake_cmake.write_text("#!/usr/bin/env bash\nexit 99\n", encoding="utf-8")
        fake_cmake.chmod(0o755)
        artifact_dir = root / "artifacts"
        artifact_dir.mkdir()
        command = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'artifact_dir="{artifact_dir}"\n'
            "set +e\n"
            "bash -c 'exit 42'\n"
            "cleanup_failed_artifacts\n"
        )
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = subprocess.run(
            ["bash", "-c", command],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(result.returncode == 42,
                "artifact cleanup masked the original failure status")
        require("failed to remove incomplete release artifacts" in result.stderr,
                "artifact cleanup failure was not reported")


def main() -> int:
    quality = load_workflow("quality.yml")
    mdns = load_workflow("mdns-compatibility.yml")
    release_workflow = load_workflow("release-artifacts.yml")

    for name, workflow in (("quality", quality), ("mDNS", mdns)):
        triggers = workflow.get("on", {})
        require(isinstance(triggers, dict), f"{name} triggers are malformed")
        require(set(triggers) >= {"push", "pull_request", "workflow_dispatch"},
                f"{name} must retain push, pull-request, and manual coverage")
        push = triggers["push"]
        require(push.get("branches") == ["main"],
                f"{name} push CI must be restricted to main")

    jobs = quality.get("jobs", {})
    newest = jobs.get("quality-newest", {})
    newest_steps = newest.get("steps", [])
    git_step = step_with(newest, "name", "Install Git for checkout")
    checkout_step = step_with(newest, "name", "Check out source")
    dependency_step = step_with(newest, "name", "Install build dependencies")
    require("git" in git_step.get("run", "").split(),
            "Debian quality must install Git for checkout")
    require(newest_steps.index(git_step) < newest_steps.index(checkout_step) <
            newest_steps.index(dependency_step),
            "Debian quality must install Git before checkout and the full gate")
    release = jobs.get("release-artifact", {})
    require(release.get("needs") == ["quality", "quality-newest"],
            "release artifact must depend on both supported quality jobs")
    require(release.get("if") == "github.event_name != 'pull_request'",
            "pull requests must not publish release artifacts")
    build_step = step_with(release, "name", "Build and test release artifact")
    require(build_step.get("run") == "./scripts/build-release-artifact.sh",
            "artifact job must execute the tested release builder")
    dependency_step = step_with(release, "name", "Install build dependencies")
    dependency_command = dependency_step.get("run", "")
    for package in ("binutils", "devscripts", "file", "gzip", "lintian"):
        require(package in dependency_command.split(),
                f"artifact job must install package validator dependency: {package}")
    upload = step_with(release, "uses", "actions/upload-artifact@v4")
    upload_options = upload.get("with", {})
    require(upload_options.get("path") == "build/release-artifacts/*",
            "artifact upload path must match the validated package directory")
    require(upload_options.get("if-no-files-found") == "error",
            "artifact upload must fail closed when the package is absent")

    gate_commands = shell_commands(ROOT / "scripts/quality-gate.sh")
    require("./scripts/validate-metadata.sh" in gate_commands,
            "metadata lint must be an executable quality-gate command")
    require("./scripts/build-release-artifact.sh" in gate_commands,
            "release mode must execute the same artifact builder as CI")
    artifact_commands = shell_commands(ROOT / "scripts/build-release-artifact.sh")
    require(
        artifact_commands.index("trap cleanup_failed_artifacts EXIT")
        < artifact_commands.index('cmake -E remove_directory "$artifact_dir"')
        < artifact_commands.index("./scripts/validate-metadata.sh"),
        "failure cleanup must cover stale removal and every later build step",
    )
    require("trap cleanup_failed_artifacts EXIT" in artifact_commands,
            "failed release builds must remove partial artifacts")
    require("trap - EXIT" in artifact_commands,
            "successful package validation must disarm failure cleanup")
    require("ctest --test-dir \"$build_dir\" --output-on-failure" in artifact_commands,
            "release artifact build must execute its CTest contracts")
    require(any(command.startswith("cpack --config ") for command in artifact_commands),
            "release artifact build must execute CPack")
    for required_command in (
        'package=$(./scripts/validate-release-artifacts.sh "$artifact_dir")',
        './scripts/validate-hardening.sh "$package" "$first_build_dir"',
        './scripts/validate-release-bundle.sh "$artifact_dir" "$version"',
    ):
        require(required_command in artifact_commands,
                f"release builder is missing: {required_command}")
    require(sum(command.startswith("cpack --config ") for command in artifact_commands) == 1,
            "the reusable two-candidate builder must contain one CPack command")

    release_triggers = release_workflow.get("on", {})
    require(release_triggers.get("push", {}).get("tags") == ["v1.0.0"],
            "release workflow must be restricted to the 1.0.0 tag")
    release_permissions = release_workflow.get("permissions", {})
    require(release_permissions == {
        "attestations": "write", "contents": "read", "id-token": "write"
    }, "release workflow has incorrect OIDC permissions")
    release_job = release_workflow.get("jobs", {}).get("release-artifacts", {})
    refusal = step_with(release_job, "name", "Refuse non-1.0 or dirty source")
    refusal_script = refusal.get("run", "")
    require("git status --porcelain" in refusal_script and
            "VERSION 1.0.0" in refusal_script,
            "release workflow must reject dirty or non-1.0 source")
    release_gate = step_with(release_job, "name", "Run full release gate")
    require(release_gate.get("run") == "./scripts/quality-gate.sh release",
            "attested artifacts must pass the exact full Release gate")
    provenance = step_with(
        release_job, "uses",
        "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
    )
    require("*.deb" in provenance.get("with", {}).get("subject-path", ""),
            "build provenance must cover the Debian package")
    require("*.spdx.json" in provenance.get("with", {}).get("subject-path", ""),
            "build provenance must cover the standalone SPDX file")
    sbom_attestation = step_with(
        release_job, "uses",
        "actions/attest-sbom@4651f806c01d8637787e274ac3bdf724ef169f34",
    )
    require(sbom_attestation.get("with", {}).get("sbom-path", "").endswith("*.spdx.json"),
            "SBOM attestation must consume the generated SPDX document")

    metadata_commands = shell_commands(ROOT / "scripts/validate-metadata.sh")
    require(any(command.startswith("appstreamcli validate --no-net --strict")
                for command in metadata_commands), "AppStream lint is missing")
    require(
        not any("--override=" in command for command in metadata_commands),
        "release-quality AppStream metadata must not rely on validator overrides",
    )

    test_release_artifact_rejection()
    test_cleanup_preserves_original_failure()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
