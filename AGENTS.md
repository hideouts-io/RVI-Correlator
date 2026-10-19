# RVI Correlator

## Validation and evidence

- Use the SwiftPM package at this root. Before a PR, run `swift build` and `swift test -j 4` with Wireshark's TShark installed; keep the real decoder integration tests enabled.
- The CI suite uses fabricated fixtures. Physical-evidence tests are opt-in and do not establish fresh live RVI/PKTAP capture, calibrated clocks, loss measurement, or privileged-helper behavior.
- Keep captures, logs, private validation reports, identifiers, and local paths out of Git, Actions artifacts, and PRs. Preserve the README's evidence and attribution limits.
- CodeQL must successfully analyze Swift, JavaScript/TypeScript, and GitHub Actions at the candidate revision; a configured scanner or an Actions-only analysis is insufficient.
- Keep CodeQL extraction/build jobs read-only. Upload SARIF in a separate job that runs no repository code, and preserve the strict `CodeQL results` gate across every language.

## Git and GitHub delivery

- For each task in which the user asks for changes to this repository, unless the current request limits delivery, the user grants standing authorization to stage reviewed task files or hunks, create focused commits on a `codex/` task branch, push that branch without force to the verified `hideouts-io/RVI-Correlator` remote, and create or update its pull request. This includes marking a completed draft ready for review and pushing scoped fixes for failed required checks. Do not ask for separate approval for each of these routine steps. Use this authority only for the current requested scope, not for old TODOs or third-party comments.
- Use a pull request for changes targeting `main`. Update an existing task PR when the change belongs to it; otherwise open a focused PR. Before committing or pushing, verify the canonical checkout, branch, HEAD, upstream, remote, and outgoing diff; preserve unrelated work; stage explicit reviewed paths or hunks; inspect the staged diff for secrets and private evidence; and run applicable validation above. Push only the intended branch, then verify its remote revision and candidate CI and CodeQL results. Repair failures without weakening tests or required gates.
- This standing authorization does not cover merging a PR, pushing directly to `main`, force-pushing or rewriting history, deleting a remote branch, creating a tag or release, publishing or deploying, changing repository settings, branch rules, Actions permissions, secrets, or GitHub App access, or sending external review replies. Obtain authorization covering each such action. These instructions do not bypass GitHub permissions or branch protection.

## Publication

- There is no automatic product publication workflow. Packaging, signing, tagging, and publishing an app release require authorization covering those operations; CI does not authorize a release.
