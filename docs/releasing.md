# macOS releases

Release builds must keep the same designated signing requirement. Replacing a
Homebrew source build with another ad-hoc signed executable can invalidate
Keychain access. The public release identity is `com.paperfoot.akm`, signed by
Developer ID Application team `S25N6MXJCF`.

1. Bump the package version, update the lockfile and changelog, and push the
   tested commit. Wait for Apple Silicon, Intel, and minimum-Rust CI jobs.
2. Download the ARM64 and X64 archives from that exact CI run. Unpack them into
   separate directories and verify their architectures and version.
3. Sign each executable on the release Mac using the existing Developer ID:

   ```sh
   codesign --force --options runtime --timestamp --identifier com.paperfoot.akm \
     --sign "Developer ID Application: SUPER SIMPLE LEARNING LTD (S25N6MXJCF)" akm
   codesign --verify --strict --verbose=2 akm
   codesign -d -r- akm
   ```

4. Verify that the signed binary can read a synthetic entry created by a prior
   signed release. For the initial signed release, test `migrate --from` against
   a working legacy binary, confirm original access, and clean up the fixture.
   Never change `HOME` for ordinary Keychain tests.
5. Repack the signed executables as `akm-arm64-apple-darwin.tar.gz` and
   `akm-x86_64-apple-darwin.tar.gz`, each containing `akm` at its root. Calculate
   SHA-256 checksums after signing. Upload archives and checksums to the GitHub
   release for the verified commit. Signing does not itself mean notarization;
   only describe an artifact as notarized after an accepted notarization result.
6. Run `cargo publish --dry-run --locked`, then `cargo publish --locked` using
   Cargo's configured credential provider. Do not print credentials.
7. Update the architecture-specific URLs and hashes in the Homebrew tap. Keep
   prebuilt executables intact: do not strip or ad-hoc re-sign them. Test the
   installed signature, version, discovery, and actual Keychain access.

Before upgrading a legacy local installation, retain its working executable and
follow the migration steps in the README. Cargo source builds remain available,
but their signing identity is the builder's responsibility. Never overwrite the
only working reader before confirming access from its replacement.
