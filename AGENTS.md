# Repository agent rules

These rules extend the workspace-level agent instructions and apply to the entire repository.

## Versioning milestone work

- Every implementation increment associated with a roadmap milestone must increment the project version in `CMakeLists.txt` and add a matching `CHANGELOG.md` entry.
- Roadmap categories are the subsection headings under `Required for 1.0` in `docs/roadmap.md`. Until `Post-1.0` is subdivided, treat `Post-1.0` itself as one category.
- The first implemented work in a new roadmap category increments the second version digit and resets the third digit to zero. The scan-configuration work establishes version `0.3.0` for the `Correctness and worker lifecycle` category.
- Category version series are contiguous. Additional implemented work that remains in the current roadmap category increments the third version digit: for example, the next increment in `Correctness and worker lifecycle` is `0.3.1`.
- Switching to a different roadmap category increments the current second digit and resets the third digit to zero. Returning to an earlier category after a switch is another category transition and starts a new minor series from the then-current version; never reuse or lower a prior version.
- Do not change the major version to `1.0.0` until every required 1.0 milestone satisfies its acceptance conditions and the roadmap records it as completed.

## Branches, verification, and publication

- Before editing, create or switch to a task-specific branch or worktree. Never perform new work directly on `main`.
- Keep each branch scoped to one human-verifiable increment. Preserve unrelated user changes and do not move them into the task branch unintentionally.
- Complete the required tests, linting, and fresh review before publication. Never review review fixes recursively.
- After a successful required review, automatically create an intentional commit containing only the verified task scope and push the task branch to its upstream remote. No separate prompt is required for that commit or push.
- Never merge a task branch into `main` until a human has verified the branch and explicitly authorized the merge. A successful automated review, push, or CI run is not human verification and does not authorize merging.
- Pushing a task branch does not authorize opening a pull request, tagging a release, publishing packages, or merging.
