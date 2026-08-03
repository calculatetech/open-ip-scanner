#!/usr/bin/env python3

import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-supported-package.sh"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ois-supported-package-") as temporary:
        root = Path(temporary)
        package = root / "candidate.deb"
        package.write_bytes(b"fixture package")
        log = root / "container-calls.jsonl"
        engine = root / "fixture-container-engine"
        engine.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "with Path(os.environ['OIS_ENGINE_LOG']).open('a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        engine.chmod(0o755)
        environment = os.environ.copy()
        environment["OIS_CONTAINER_ENGINE"] = str(engine)
        environment["OIS_ENGINE_LOG"] = str(log)

        result = subprocess.run(
            [str(VALIDATOR), str(package)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(result.returncode == 0, "valid package path was rejected")
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        require(len(calls) == 2, "validator did not invoke both supported images")
        require([call[call.index("sh") - 1] for call in calls] ==
                ["ubuntu:24.04", "debian:13"],
                "validator used the wrong supported images or order")
        for call in calls:
            require(call[:3] == ["run", "--pull=always", "--rm"],
                    "container lifecycle flags changed")
            mount = call[call.index("--mount") + 1]
            require(f"source={package.resolve()}" in mount and "readonly" in mount,
                    "candidate package was not mounted read-only")
            command = call[-1]
            for expected in (
                "apt-get install -y /tmp/open-ip-scanner.deb",
                "dpkg --status open-ip-scanner",
                "ldd /usr/bin/open-ip-scanner",
                "QT_QPA_PLATFORM=offscreen",
                "--startup-smoke",
                "apt-get remove -y open-ip-scanner",
            ):
                require(expected in command,
                        f"container validation is missing: {expected}")

        missing = subprocess.run(
            [str(VALIDATOR), str(root / "missing.deb")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(missing.returncode == 2, "missing package did not fail usage validation")

        failing_engine = root / "failing-container-engine"
        failing_engine.write_text("#!/usr/bin/env bash\nexit 29\n", encoding="utf-8")
        failing_engine.chmod(0o755)
        environment["OIS_CONTAINER_ENGINE"] = str(failing_engine)
        failed = subprocess.run(
            [str(VALIDATOR), str(package)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        require(failed.returncode == 29,
                "container-engine failure status was not preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
