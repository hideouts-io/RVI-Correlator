# RVI Correlator

## Validation and evidence

- Use the SwiftPM package at this root. Before a PR, run `swift build` and `swift test -j 4` with Wireshark's TShark installed; keep the real decoder integration tests enabled.
- The CI suite uses fabricated fixtures. Physical-evidence tests are opt-in and do not establish fresh live RVI/PKTAP capture, calibrated clocks, loss measurement, or privileged-helper behavior.
- Keep captures, logs, private validation reports, identifiers, and local paths out of Git, Actions artifacts, and PRs. Preserve the README's evidence and attribution limits.
- CodeQL must successfully analyze Swift, JavaScript/TypeScript, and GitHub Actions at the candidate revision; a configured scanner or an Actions-only analysis is insufficient.
- Keep CodeQL extraction/build jobs read-only. Upload SARIF in a separate job that runs no repository code, and preserve the strict `CodeQL results` gate across every language.

## Publication

- There is no automatic product publication workflow. Packaging, signing, tagging, and publishing an app release require authorization covering those operations; CI does not authorize a release.
