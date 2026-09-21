# Third-party notices

MicroCard is AGPL-3.0-or-later. Its build resolves third-party dependencies under their own licenses.

The Java wallet uses:

- GlobalPlatformPro, LGPL-3.0-or-later and MIT-licensed components, pinned in `docs/GLOBALPLATFORMPRO_PIN.json`.
- Bouncy Castle through GlobalPlatformPro, MIT license.
- Gson, Apache-2.0.
- SLF4J, MIT license.
- JUnit Jupiter for tests, EPL-2.0.

The vendored JCAlgTest v1.8.2 Java Card applet is MIT licensed. Its source
revision, local compatibility patch, artifact hashes, and license are recorded
in `vendor/jcalgtest`.

Rust and .NET dependency versions are fixed by `Cargo.lock` and NuGet lock files. Bundled Java archives retain their embedded manifests and notices. This file does not replace the license files or notices supplied with those dependencies.
