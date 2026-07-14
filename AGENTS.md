# Repository agent rules

These rules extend the workspace-level agent instructions and apply to the entire repository.

## Versioning milestone work

- Every implementation increment associated with a roadmap milestone must increment the project version in `CMakeLists.txt` and add a matching `CHANGELOG.md` entry.
- Versions form one monotonic development sequence; roadmap categories may be interleaved without creating a new minor series.
- The first implementation in a deliberately selected new development series increments the second digit and resets the third digit. The human-verified Settings layout establishes `0.4.0` as the current series baseline.
- Every subsequent implementation increment increases the third digit unless the user explicitly authorizes starting another minor series. Returning to correctness work after `0.4.0` therefore produces `0.4.1`, not `0.5.0` and never a reused `0.3.x` version.
- Documentation-only corrections to policy, plans, or roadmap progress do not increment the application version unless they change shipped application behavior.
- Do not change the major version to `1.0.0` until every required 1.0 milestone satisfies its acceptance conditions and the roadmap records it as completed.

## Branches, verification, and publication

- Before editing, create or switch to a task-specific branch or worktree. Never perform new work directly on `main`.
- Keep each branch scoped to one human-verifiable increment. Preserve unrelated user changes and do not move them into the task branch unintentionally.
- Complete the required tests, linting, and fresh review before publication. Never review review fixes recursively.
- After a successful required review, automatically create an intentional commit containing only the verified task scope and push the task branch to its upstream remote. No separate prompt is required for that commit or push.
- Never merge a task branch into `main` until a human has verified the branch and explicitly authorized the merge. A successful automated review, push, or CI run is not human verification and does not authorize merging.
- Pushing a task branch does not authorize opening a pull request, tagging a release, publishing packages, or merging.
