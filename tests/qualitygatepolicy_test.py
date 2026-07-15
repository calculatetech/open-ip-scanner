#!/usr/bin/env python3

from pathlib import Path
import json
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


def build_test_package(
    output: Path, version: str, marker: str, architecture: str = "amd64"
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ois-deb-root-", dir=output.parent) as temporary:
        package_root = Path(temporary)
        control = package_root / "DEBIAN"
        control.mkdir()
        (control / "control").write_text(
            "Package: open-ip-scanner\n"
            f"Version: {version}\n"
            f"Architecture: {architecture}\n"
            "Maintainer: Test Fixture <fixture@example.invalid>\n"
            "Description: Publication policy fixture\n",
            encoding="utf-8",
        )
        payload = package_root / "usr/share/open-ip-scanner"
        payload.mkdir(parents=True)
        (payload / "marker").write_text(marker, encoding="utf-8")
        subprocess.run(
            ["dpkg-deb", "--build", str(package_root), str(output)],
            check=True,
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
        package_root = root / "package-scratch"
        package_root.mkdir()
        command = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'package_root="{package_root}"\n'
            "set +e\n"
            "bash -c 'exit 42'\n"
            "cleanup_transient_output\n"
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
        require("failed to remove transient release output" in result.stderr,
                "transient cleanup failure was not reported")


def test_provenance_destination_safety() -> None:
    with tempfile.TemporaryDirectory(prefix="ois-provenance-policy-") as temporary:
        temporary_root = Path(temporary)
        existing = temporary_root / "existing"
        existing.mkdir()
        sentinel = existing / "keep"
        sentinel.write_text("keep", encoding="utf-8")
        real_parent = temporary_root / "real-parent"
        real_parent.mkdir()
        linked_parent = temporary_root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)

        for destination, expected_error in (
            ("relative-output", "must be an absolute path"),
            (str(existing), "must not already exist"),
            (str(linked_parent / "output"), "parent must not traverse symlinks"),
            (str(ROOT / "nested-output"), "must be outside the repository"),
        ):
            command = (
                f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
                f'root="{ROOT}"\n'
                f'provenance_dir="{destination}"\n'
                "prepare_provenance_directory\n"
            )
            result = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            require(result.returncode != 0,
                    f"unsafe provenance destination was accepted: {destination}")
            require(expected_error in result.stderr,
                    f"unsafe provenance rejection was unclear: {destination}")
        require(sentinel.read_text(encoding="utf-8") == "keep",
                "existing provenance destination was modified")

        safe = temporary_root / "new-provenance"
        command = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'root="{ROOT}"\n'
            f'provenance_dir="{safe}"\n'
            "prepare_provenance_directory\n"
            "test \"$provenance_owned\" -eq 1\n"
            "set +e\n"
            "bash -c 'exit 42'\n"
            "cleanup_transient_output\n"
        )
        result = subprocess.run(
            ["bash", "-c", command],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        require(result.returncode == 42,
                "owned provenance cleanup masked the original failure")
        require(not safe.exists(),
                "owned provenance output survived a failed build")

        raced = temporary_root / "raced-provenance"
        fake_bin = temporary_root / "race-bin"
        fake_bin.mkdir()
        fake_mkdir = fake_bin / "mkdir"
        fake_mkdir.write_text(
            "#!/usr/bin/env bash\n"
            "/usr/bin/mkdir -- \"$2\"\n"
            "touch \"$2/keep\"\n"
            "exit 1\n",
            encoding="utf-8",
        )
        fake_mkdir.chmod(0o755)
        command = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'root="{ROOT}"\n'
            f'provenance_dir="{raced}"\n'
            "set +e\n"
            "prepare_provenance_directory\n"
            "status=$?\n"
            "test \"$provenance_owned\" -eq 0\n"
            "exit \"$status\"\n"
        )
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = subprocess.run(
            ["bash", "-c", command], cwd=ROOT,
            capture_output=True, text=True, check=False, env=environment,
        )
        require(result.returncode != 0,
                "losing provenance directory race was accepted")
        require((raced / "keep").exists(),
                "directory created by a competing process was deleted")


def test_failed_publish_preserves_existing_package() -> None:
    with tempfile.TemporaryDirectory(prefix="ois-publish-policy-") as temporary:
        temporary_root = Path(temporary)
        release = temporary_root / "release"
        release.mkdir()
        existing = release / "open-ip-scanner_0.7.7_amd64.deb"
        build_test_package(existing, "0.7.7", "previous validated package")
        existing_bytes = existing.read_bytes()
        candidate = temporary_root / "candidate" / existing.name
        build_test_package(candidate, "0.7.7", "replacement package")

        staged_failure = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'release_dir="{release}"\n'
            "trap cleanup_transient_output EXIT\n"
            f'stage_release_package "{candidate}"\n'
            "false\n"
        )
        result = subprocess.run(
            ["bash", "-c", staged_failure],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        require(result.returncode != 0,
                "injected post-staging failure unexpectedly succeeded")
        require(existing.read_bytes() == existing_bytes,
                "post-staging failure replaced the previous package")
        require(not list(release.glob(".open-ip-scanner-package.*.tmp")),
                "post-staging failure left its temporary package behind")

        fake_bin = temporary_root / "bin"
        fake_bin.mkdir()
        fake_mv = fake_bin / "mv"
        fake_mv.write_text("#!/usr/bin/env bash\nexit 73\n", encoding="utf-8")
        fake_mv.chmod(0o755)
        command = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'release_dir="{release}"\n'
            f'stage_release_package "{candidate}"\n'
            "publish_staged_release\n"
        )
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = subprocess.run(
            ["bash", "-c", command],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
        require(result.returncode == 73,
                "publish failure did not preserve the rename status")
        require("publishing installable package" not in result.stdout and
                "installable package:" not in result.stdout,
                "failed publication reported a package as installed")
        require(existing.read_bytes() == existing_bytes,
                "failed publication destroyed the previous validated package")


def test_publish_retains_other_versions() -> None:
    with tempfile.TemporaryDirectory(prefix="ois-publish-retention-") as temporary:
        temporary_root = Path(temporary)
        release = temporary_root / "release"
        release.mkdir()
        previous = release / "open-ip-scanner_0.7.6_amd64.deb"
        build_test_package(previous, "0.7.6", "previous version")
        previous_bytes = previous.read_bytes()
        sentinel = release / ".open-ip-scanner-package.tmp"
        sentinel.write_text("human-controlled sentinel", encoding="utf-8")
        same_version = release / "open-ip-scanner_0.7.7_amd64.deb"
        build_test_package(same_version, "0.7.7", "previous same-version build")
        candidate = temporary_root / "candidate" / same_version.name
        build_test_package(candidate, "0.7.7", "replacement package")
        candidate_bytes = candidate.read_bytes()
        command = (
            f'source "{ROOT / "scripts/build-release-artifact.sh"}"\n'
            f'release_dir="{release}"\n'
            f'stage_release_package "{candidate}"\n'
            "publish_staged_release\n"
        )
        subprocess.run(["bash", "-c", command], cwd=ROOT, check=True)
        require(previous.read_bytes() == previous_bytes,
                "publishing removed a human-controlled previous release")
        require(sentinel.read_text(encoding="utf-8") == "human-controlled sentinel",
                "publishing modified a noncanonical release entry")
        require(same_version.read_bytes() == candidate_bytes,
                "publishing did not replace the same-version package")


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
    checkout_dependencies = step_with(newest, "name", "Install checkout dependencies")
    checkout_step = step_with(newest, "name", "Check out source")
    trust_step = step_with(newest, "name", "Trust checked-out source")
    dependency_step = step_with(newest, "name", "Install build dependencies")
    gate_step = step_with(newest, "name", "Run full quality gate")
    checkout_command = checkout_dependencies.get("run", "")
    require("apt-get install -y --no-install-recommends ca-certificates git" in
            " ".join(checkout_command.split()),
            "Debian quality must install CA certificates and Git for checkout")
    require(checkout_step.get("uses") == "actions/checkout@v5",
            "Debian quality must use the audited checkout action")
    require(trust_step.get("run") ==
            'git config --global --add safe.directory "$GITHUB_WORKSPACE"',
            "Debian quality must persist trust for the checked-out workspace")
    require(gate_step.get("run") == "./scripts/quality-gate.sh full",
            "Debian quality must execute the full gate")
    require(newest_steps.index(checkout_dependencies) < newest_steps.index(checkout_step) <
            newest_steps.index(trust_step) <
            newest_steps.index(dependency_step) < newest_steps.index(gate_step),
            "Debian quality must prepare Git, check out, then trust source before the full gate")
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
    require(upload_options.get("path") == "release/*.deb",
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
        artifact_commands.index("trap cleanup_transient_output EXIT")
        < artifact_commands.index('cmake -E remove_directory "$package_root"')
        < artifact_commands.index("./scripts/validate-metadata.sh"),
        "transient cleanup must cover stale removal and every later build step",
    )
    require("trap cleanup_transient_output EXIT" in artifact_commands,
            "release builds must remove transient output on failure")
    require("trap - EXIT" in artifact_commands,
            "successful package validation must disarm failure cleanup")
    require("ctest --test-dir \"$build_dir\" --output-on-failure" in artifact_commands,
            "release artifact build must execute its CTest contracts")
    require(any(command.startswith("cpack --config ") for command in artifact_commands),
            "release artifact build must execute CPack")
    for required_command in (
        'package=$(./scripts/validate-release-artifacts.sh "$bundle_dir")',
        './scripts/validate-hardening.sh "$package" "$first_build_dir"',
        './scripts/validate-release-bundle.sh "$bundle_dir" "$version"',
        'cmake -E remove_directory "$package_root"',
        'cmake -E remove_directory "$bundle_dir"',
        'stage_release_package "$package"',
        "publish_staged_release",
    ):
        require(required_command in artifact_commands,
                f"release builder is missing: {required_command}")
    stage_index = artifact_commands.index('stage_release_package "$package"')
    package_cleanup_index = artifact_commands.index(
        'cmake -E remove_directory "$package_root"', stage_index
    )
    bundle_cleanup_index = artifact_commands.index(
        'cmake -E remove_directory "$bundle_dir"', package_cleanup_index
    )
    publish_index = artifact_commands.index("publish_staged_release", bundle_cleanup_index)
    require(
        stage_index < package_cleanup_index < bundle_cleanup_index < publish_index,
        "same-version replacement must be the terminal fallible release operation",
    )
    require('echo "publishing installable package: $release_dir/$(basename "$package")"' in
            artifact_commands and
            not any(command.startswith('echo "installable package:')
                    for command in artifact_commands),
            "pre-publication output must be prospective rather than claim success")
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
    require(release_gate.get("env", {}).get("OIS_PROVENANCE_DIR") ==
            "${{ runner.temp }}/open-ip-scanner-provenance",
            "release provenance must use the runner temporary directory")
    provenance = step_with(
        release_job, "uses",
        "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
    )
    provenance_paths = provenance.get("with", {}).get("subject-path", "")
    require(provenance_paths.splitlines() == [
        "release/*.deb",
        "${{ runner.temp }}/open-ip-scanner-provenance/*.tar.gz",
        "${{ runner.temp }}/open-ip-scanner-provenance/*.spdx.json",
        "${{ runner.temp }}/open-ip-scanner-provenance/SHA256SUMS",
    ], "build provenance must cover the exact canonical release bundle")
    sbom_attestation = step_with(
        release_job, "uses",
        "actions/attest-sbom@4651f806c01d8637787e274ac3bdf724ef169f34",
    )
    require(sbom_attestation.get("with", {}).get("subject-path") ==
            "release/*.deb",
            "SBOM subject must use the exact canonical package path")
    require(sbom_attestation.get("with", {}).get("sbom-path") ==
            "${{ runner.temp }}/open-ip-scanner-provenance/*.spdx.json",
            "SBOM attestation must use the exact canonical SPDX path")
    package_upload = step_with(release_job, "name", "Upload verified installable package")
    require(package_upload.get("with", {}).get("path") == "release/*.deb",
            "verified release upload must contain only installable packages")
    provenance_upload = step_with(release_job, "name", "Upload verification material")
    require(provenance_upload.get("with", {}).get("path") ==
            "${{ runner.temp }}/open-ip-scanner-provenance/*",
            "verification material must remain separate from installable packages")
    require("prepare_provenance_directory" in artifact_commands,
            "release builder must validate and own its provenance destination")
    require(any('"$bundle_dir/open-ip-scanner-$version.tar.gz"' in command
                for command in artifact_commands) and
            any('"$bundle_dir/open-ip-scanner_${version}_amd64.spdx.json"' in command
                for command in artifact_commands) and
            any('"$bundle_dir/SHA256SUMS"' in command
                for command in artifact_commands) and
            not any("> SHA256SUMS" in command for command in artifact_commands),
            "verification material must preserve the complete bundle checksums")

    presets = json.loads((ROOT / "CMakePresets.json").read_text(encoding="utf-8"))
    preset_directories = {
        preset.get("name"): preset.get("binaryDir")
        for preset in presets.get("configurePresets", [])
    }
    require(preset_directories == {
        "dev": "${sourceDir}/build/dev",
        "release": "${sourceDir}/build/release",
        "asan-ubsan": "${sourceDir}/build/asan-ubsan",
        "tsan": "${sourceDir}/build/tsan",
        "clang-tidy": "${sourceDir}/build/clang-tidy",
    }, "configure presets must use their exact canonical build directories")
    ignore_lines = set(shell_commands(ROOT / ".gitignore"))
    require("/build/" in ignore_lines,
            "the canonical build root must be ignored")
    require("/release/" in ignore_lines,
            "the installable package directory must be ignored")
    for legacy_ignore in ("build-*/", "cmake-build-*/", "_CPack_Packages/", "*.deb"):
        require(legacy_ignore not in ignore_lines,
                f"legacy top-level output must not be hidden: {legacy_ignore}")
    docker_ignore_lines = set(shell_commands(ROOT / ".dockerignore"))
    for generated_context in (
        "build", "release", "build-*", "cmake-build-*", "_CPack_Packages", "*.deb"
    ):
        require(generated_context in docker_ignore_lines,
                f"Docker context must exclude generated output: {generated_context}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require("./build/dev/open-ip-scanner" in readme,
            "README must identify the stable validation binary")
    require("other releases are retained" in readme,
            "README must document human-controlled release retention")
    audit_plan = (ROOT / "docs/execplans/1.0-production-readiness-audit.md").read_text(
        encoding="utf-8"
    )
    require("build-audit" not in audit_plan,
            "maintained audit reproduction paths must stay beneath build/")
    require('set(CPACK_PACKAGE_DIRECTORY "${CMAKE_BINARY_DIR}/package-scratch")' in
            (ROOT / "CMakeLists.txt").read_text(encoding="utf-8"),
            "direct CPack scratch output must remain inside its build directory")
    maintained_paths = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "scripts/quality-gate.sh",
            "scripts/validate-metadata.sh",
            "scripts/build-release-artifact.sh",
            ".github/workflows/quality.yml",
            ".github/workflows/release-artifacts.yml",
        )
    )
    for legacy_path in (
        "build/quality-",
        "build/metadata-lint",
        "build/release-repro-",
        "build/release-package-",
        "build/release-artifacts",
        "build/artifacts/release",
    ):
        require(legacy_path not in maintained_paths,
                f"maintained automation still uses legacy output: {legacy_path}")

    metadata_commands = shell_commands(ROOT / "scripts/validate-metadata.sh")
    require(any(command.startswith("appstreamcli validate --no-net --strict")
                for command in metadata_commands), "AppStream lint is missing")
    require(
        not any("--override=" in command for command in metadata_commands),
        "release-quality AppStream metadata must not rely on validator overrides",
    )

    test_release_artifact_rejection()
    test_cleanup_preserves_original_failure()
    test_provenance_destination_safety()
    test_failed_publish_preserves_existing_package()
    test_publish_retains_other_versions()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
