# Changelog

## 0.1-wip

Initial development release:

- reduced .NET/CIL assembly toolchain and Rust interpreter.
- signed package loading, verified linking, security domains, SCP03, and transactional persistence.
- native cryptography and opaque credential keys.
- Java/GlobalPlatformPro credential wallet and simulator demonstration.
- bare-metal nRF52840 development image.
- Roslyn analyzer package and Rider workflow.
- USB CCID enumeration on the nRF52840 DK, carrying SCP03 through GlobalPlatformPro at every security level that carries a command MAC.
- SCP03 implementation option `0x71`, adding S16 mode, a derived card challenge and R-ENCRYPTION, with the advertised option and the accepted security levels both derived from the enabled cargo features.
- a Java Card virtual machine in `crates/microcard-engine-jcvm`, covering the CAP container, structural verification of a whole package, an object heap with firewall checks, linking, the bytecode interpreter and the native API classes.
- OpenFIPS201 installing, registering, accepting a SELECT and answering PIV commands in the simulator, with its own PIN retry counter persisting across commands.
