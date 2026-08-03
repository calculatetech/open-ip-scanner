#!/usr/bin/env python3

"""Make selected Qt 6 shlib dependencies portable across Ubuntu and Debian."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


PORTABLE_QT_MODULES = (
    "dbus",
    "gui",
    "network",
    "printsupport",
    "widgets",
)
REQUIRED_DEPENDENCIES = (
    "iputils-ping",
    "iproute2",
    "libc6",
    "libgcc-s1",
    "libqt6core6t64",
    "libstdc++6",
)
DEPENDENCY_PREFIX = "shlibs:Depends="
RELATION_PATTERN = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9+.-]*)"
    r"(?P<constraint> \((?:<<|<=|=|>=|>>) "
    r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~]*(?:-[A-Za-z0-9.+~]+)*\))?$"
)


class DependencyError(RuntimeError):
    """Raised when dependency metadata is unsafe or ambiguous."""


def split_relations(value: str) -> list[str]:
    relations = [relation.strip() for relation in value.split(",")]
    if not relations or any(not relation for relation in relations):
        raise DependencyError("dependency list contains an empty relation")
    return relations


def parse_simple_relation(relation: str) -> tuple[str, str]:
    match = RELATION_PATTERN.fullmatch(relation)
    if not match:
        raise DependencyError(f"unsupported dependency relation: {relation}")
    return match.group("name"), match.group("constraint") or ""


def portable_names(module: str) -> tuple[str, str]:
    base = f"libqt6{module}6"
    return f"{base}t64", base


def normalize_depends(value: str) -> str:
    normalized: list[str] = []
    seen: set[str] = set()

    for relation in split_relations(value):
        if "|" in relation:
            raise DependencyError(
                f"dpkg-shlibdeps emitted an unexpected alternative: {relation}"
            )
        name, constraint = parse_simple_relation(relation)
        module = next(
            (
                candidate
                for candidate in PORTABLE_QT_MODULES
                if name in portable_names(candidate)
            ),
            None,
        )
        if module is None:
            normalized.append(relation)
            continue
        if not constraint:
            raise DependencyError(f"Qt dependency lacks a version relation: {name}")
        if module in seen:
            raise DependencyError(f"duplicate Qt dependency for module: {module}")
        seen.add(module)
        t64_name, unsuffixed_name = portable_names(module)
        normalized.append(
            f"{t64_name}{constraint} | {unsuffixed_name}{constraint}"
        )

    missing = sorted(set(PORTABLE_QT_MODULES) - seen)
    if missing:
        raise DependencyError(
            "dpkg-shlibdeps omitted required Qt modules: " + ", ".join(missing)
        )
    return ", ".join(normalized)


def normalize_output(output: str) -> str:
    lines = output.splitlines(keepends=True)
    dependency_indexes = [
        index for index, line in enumerate(lines) if line.startswith(DEPENDENCY_PREFIX)
    ]
    if len(dependency_indexes) != 1:
        raise DependencyError(
            "dpkg-shlibdeps output must contain exactly one shlibs:Depends field"
        )
    index = dependency_indexes[0]
    line = lines[index]
    newline = "\n" if line.endswith("\n") else ""
    value = line[len(DEPENDENCY_PREFIX) :].rstrip("\r\n")
    lines[index] = DEPENDENCY_PREFIX + normalize_depends(value) + newline
    return "".join(lines)


def validate_final_depends(value: str) -> None:
    relations = split_relations(value)

    simple_names: list[str] = []
    portable_seen: set[str] = set()
    for relation in relations:
        if "|" not in relation:
            name, _ = parse_simple_relation(relation)
            simple_names.append(name)
            if name.startswith("libqt6") and name != "libqt6core6t64":
                raise DependencyError(
                    f"standalone or unknown Qt dependency remains: {relation}"
                )
            continue

        alternatives = [item.strip() for item in relation.split("|")]
        if len(alternatives) != 2:
            raise DependencyError(f"unexpected dependency alternatives: {relation}")
        first_name, first_constraint = parse_simple_relation(alternatives[0])
        second_name, second_constraint = parse_simple_relation(alternatives[1])
        module = next(
            (
                candidate
                for candidate in PORTABLE_QT_MODULES
                if (first_name, second_name) == portable_names(candidate)
            ),
            None,
        )
        if module is None:
            raise DependencyError(f"noncanonical dependency alternatives: {relation}")
        if not first_constraint or first_constraint != second_constraint:
            raise DependencyError(
                f"Qt alternatives have missing or unequal constraints: {relation}"
            )
        if module in portable_seen:
            raise DependencyError(f"duplicate portable Qt module: {module}")
        portable_seen.add(module)

    missing_modules = sorted(set(PORTABLE_QT_MODULES) - portable_seen)
    if missing_modules:
        raise DependencyError(
            "package is missing portable Qt modules: " + ", ".join(missing_modules)
        )
    for dependency in REQUIRED_DEPENDENCIES:
        if simple_names.count(dependency) != 1:
            raise DependencyError(
                f"package must contain exactly one {dependency} dependency"
            )


def backend_path() -> str:
    configured = os.environ.get("OIS_DPKG_SHLIBDEPS_EXECUTABLE")
    backend = configured or shutil.which("dpkg-shlibdeps")
    if not backend:
        raise DependencyError("could not find the real dpkg-shlibdeps executable")
    resolved = Path(backend).resolve()
    if resolved == Path(__file__).resolve():
        raise DependencyError("dpkg-shlibdeps wrapper resolved to itself")
    return str(resolved)


def run_backend(arguments: list[str]) -> int:
    try:
        result = subprocess.run(
            [backend_path(), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, DependencyError) as error:
        print(f"portable dpkg-shlibdeps: {error}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    output = result.stdout
    if "-O" in arguments:
        try:
            output = normalize_output(output)
        except DependencyError as error:
            sys.stderr.write(result.stderr)
            print(f"portable dpkg-shlibdeps: {error}", file=sys.stderr)
            return 1
    sys.stdout.write(output)
    sys.stderr.write(result.stderr)
    return 0


def main(arguments: list[str]) -> int:
    if len(arguments) == 2 and arguments[0] == "--ois-validate-depends":
        try:
            validate_final_depends(arguments[1])
        except DependencyError as error:
            print(f"portable dpkg-shlibdeps: {error}", file=sys.stderr)
            return 1
        return 0
    return run_backend(arguments)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
