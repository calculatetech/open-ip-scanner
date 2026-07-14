# Repository agent rules

These rules extend the workspace-level agent instructions and apply to the entire repository.

## Versioning milestone work

- Creating a new implementation task branch from `main` increments the application version in `CMakeLists.txt` and opens the matching dated section in `CHANGELOG.md`. Roadmap categories may be interleaved without creating a new minor series; start another minor series only when the user explicitly authorizes it.
- That branch owns its version until human verification and merge. Implementation changes, review fixes, and human-validation fixes on the branch never increment it again.
- Do not create or assign a later-version implementation branch while the current version branch remains unmerged. After the current version is human-verified and merged, the next implementation branch increments the third digit.
- If a version branch is explicitly abandoned or replaced before merge, its replacement reuses that unmerged version rather than consuming another number.
- Documentation-only corrections to policy, plans, or roadmap progress do not increment the application version unless they change shipped application behavior.
- Do not change the major version to `1.0.0` until every required 1.0 milestone satisfies its acceptance conditions and the roadmap records it as completed.

## Branches, verification, and publication

- Before editing, create or switch to a task-specific branch or worktree. Never perform new work directly on `main`.
- Keep each branch scoped to one human-verifiable increment. Preserve unrelated user changes and do not move them into the task branch unintentionally.
- Complete the required tests, linting, and fresh review before publication. Never review review fixes recursively.
- After a successful required review, automatically create an intentional commit containing only the verified task scope and push the task branch to its upstream remote. No separate prompt is required for that commit or push.
- Never merge a task branch into `main` until a human has verified the branch and explicitly authorized the merge. A successful automated review, push, or CI run is not human verification and does not authorize merging.
- Pushing a task branch does not authorize opening a pull request, tagging a release, publishing packages, or merging.
