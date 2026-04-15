# Android Scanner

`android-scanner` is the native Android port of the DNS scan stage from `mini-resolver`.

This first scaffold includes:

- a Kotlin Android app with a Compose UI shell
- target parsing for IPv4 CIDRs and single IPs
- prefix normalization, host counting, and host walking logic
- a foreground service and repository-driven scan runtime surface
- a real DNS scan engine with UDP, TCP, and BOTH protocol support
- the six mini-resolver compatibility probes and resolver scoring
- transparent DNS proxy detection for UDP-based scans

What is not ported yet:

- result export and persistence
- RIPE/operator lookup
- instrumented integration tests against local DNS test servers

## Open The Project

The project is set up as a standard Android Studio / Gradle app.

Build requirements:

- JDK 17
- Go 1.24.1, used to compile the bundled DNSTT helper
- Android SDK with API 34 / Build Tools 34
- Gradle or Android Studio's bundled Gradle support

This machine only exposed Java 8 and no local Gradle installation while the scaffold was created, so the project files were written but not compiled locally yet.

## Release Builds

Build pipelines are release-only. They run when a Git tag is pushed, not on
regular branch pushes.

GitHub Actions:

- `.github/workflows/android-release.yml` runs only for pushed tags.
- `verify` runs Android JVM unit tests and DNSTT helper Go tests.
- `build-apks` runs `:app:assembleDebug` and `:app:assembleRelease`, then uploads APK artifacts.

GitLab CI:

- `.gitlab-ci.yml` is also restricted to tag pipelines through `workflow: rules`.
- `verify` and `build` match the GitHub release workflow.

Create a release build with:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The Android build enables an `arm64-v8a` APK plus a universal APK. The bundled
DNSTT helper is currently packaged for `arm64-v8a`, which is the only Android
ABI supported by the current pure-Go helper build without Android NDK cgo
linkers.

- `arm64-v8a`
- universal APK

If 32-bit ARM or emulator-specific x86/x86_64 DNSTT helper binaries are needed,
add Android NDK installation to CI and wire Go's `CC`/`CGO_ENABLED=1` settings
for those targets.

Do not commit APKs, AABs, keystores, `local.properties`, `.gradle*`, or `build` outputs. The `.gitignore` keeps those local/generated files out of Git, and tag-triggered CI should be the place where APK artifacts are produced.

Release APKs built by the default pipeline are unsigned unless signing is added through protected CI secrets. Keep signing keys and passwords in GitHub Actions secrets or GitLab CI/CD variables, not in this repository.

## Project Layout

- `app/src/main/java/com/pedrammarandi/androidscanner/scan/input`
  - IPv4 parsing, normalization, and host walking
- `app/src/main/java/com/pedrammarandi/androidscanner/scan/model`
  - UI and runtime models
- `app/src/main/java/com/pedrammarandi/androidscanner/scan/runtime`
  - foreground service, repository, controller, and DNS scan engine
- `app/src/main/java/com/pedrammarandi/androidscanner/ui`
  - Compose screen and ViewModel

## Next Porting Steps

The next meaningful implementation steps are:

- add result export and scan-session persistence
- add RIPE/operator lookup
- add JVM and Android integration tests that hit fake UDP/TCP DNS servers
- refine the UI for large result sets and background resumption

The current DNS scan logic was ported from:

- `mini-resolver/internal/scanner/scanner.go`
- `mini-resolver/internal/prefixes/prefixes.go`
