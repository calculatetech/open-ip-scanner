# Repository agent rules

These rules extend the workspace-level agent instructions and apply to the entire repository.

## Versioning milestone work

- The version in `CMakeLists.txt` always identifies the latest human-verified increment merged to `main`. Task branches must retain that version and record their pending application changes under an `Unreleased` heading in `CHANGELOG.md`.
- Versions form one monotonic development sequence; roadmap categories may be interleaved without creating a new minor series. The human-verified Settings layout establishes `0.4.0` as the current merged baseline.
- A pending increment receives no version number until a human verifies it and explicitly authorizes its merge. Abandoned, superseded, or rejected branches consume no version numbers.
- During the authorized merge, use a no-commit merge, increment the third digit in `CMakeLists.txt`, convert the branch's `Unreleased` changelog heading to that version and date, and include those metadata edits in the merge commit. Start another minor series only when the user explicitly authorizes it.
- Documentation-only corrections to policy, plans, or roadmap progress do not increment the application version unless they change shipped application behavior.
- Do not change the major version to `1.0.0` until every required 1.0 milestone satisfies its acceptance conditions and the roadmap records it as completed.

## Branches, verification, and publication

- Before editing, create or switch to a task-specific branch or worktree. Never perform new work directly on `main`.
- Keep each branch scoped to one human-verifiable increment. Preserve unrelated user changes and do not move them into the task branch unintentionally.
- Complete the required tests, linting, and fresh review before publication. Never review review fixes recursively.
- After a successful required review, automatically create an intentional commit containing only the verified task scope and push the task branch to its upstream remote. No separate prompt is required for that commit or push.
- Never merge a task branch into `main` until a human has verified the branch and explicitly authorized the merge. A successful automated review, push, or CI run is not human verification and does not authorize merging.
- Human merge authorization also authorizes the merge-time-only version and changelog metadata edits described above. It does not authorize any other source or behavior change.
- Pushing a task branch does not authorize opening a pull request, tagging a release, publishing packages, or merging.
