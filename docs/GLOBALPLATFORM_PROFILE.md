# GlobalPlatform management profile

MicroCard implements a deliberately bounded subset of GlobalPlatform Card Specification 2.3.1. This interoperability profile makes no claim of full GlobalPlatform conformance.

## Discovery

The basic channel accepts ISO SELECT by DF name for the GlobalPlatform default Issuer Security Domain AID `A000000151000000`, and the empty default-selection form used for ISD discovery, before authentication. A successful selection returns an FCI template containing that AID and ends any existing secure-channel session. Its proprietary data advertises GlobalPlatform 2.3.1, the SCP03 implementation option this build derives from its enabled capabilities and a conservative 224-byte command-data ceiling.

Before SCP03 authentication, GlobalPlatform GET DATA `0066` returns Appendix H format-1 Card Recognition Data. Optional CPLC, IIN, CIN and key-information objects are absent and return `6A88`. No fabricated production identity is exposed. Once a secure channel is active, an unsecured GET DATA fails secure messaging and tears down that session. The same Card Recognition Data is available through authenticated secure messaging.

Registry enumeration uses GlobalPlatform 2.3.1 §11.4 GET STATUS with modern TLV responses:

- P1 `80`: ISD
- P1 `40`: installed application instances and SSDs
- P1 `20`: assemblies
- P1 `10`: assemblies and their executable modules
- P2 `02`: first occurrence
- P2 `03`: next occurrence

Command data starts with the mandatory `4F` AID search qualifier. An empty value selects all records. A five-byte RID value selects every matching proprietary AID. Additional well-formed qualifiers are currently ignored as permitted by §11.4.2.3. Deprecated P2 formats, malformed TLVs and invalid continuation requests return `6A80`. An empty result returns `6A88`.

One `E3` registry record is returned per short APDU. `6310` indicates another record and `9000` ends the sequence. Continuation state lives only in the active secure-channel session and is cleared by another command, a new authentication attempt, ISD selection or an error.

GET STATUS requires an authenticated SCP03 session carrying a command MAC. The public SELECT response exposes only the fixed ISD identity.

## Registry mapping

The response fields follow Tables 11-36 and 11-37:

- `4F`: entity AID
- `9F70`: lifecycle
- `C5`: three-byte privileges for the ISD, SSDs and installed instances
- `C4`: an installed instance's assembly AID
- `CE`: the assembly's four-part .NET version encoded as four big-endian 16-bit integers
- `84`: an executable module AID
- `CC`: associated security-domain AID

The ISD reports OP_READY (`01`) until `mscorlib` takes ownership, then SECURED (`0F`). An unbound SSD reports SELECTABLE (`07`). A signer-bound SSD reports PERSONALIZED (`0F`). Installed instances report SELECTABLE (`07`) and assemblies report LOADED (`01`). ISD and SSD records carry the Security Domain privilege (`80 00 00`). Instances carry no privilege.

Installed-instance AIDs come from signed assembly metadata. An SSD created through standard management keeps its requested AID as its durable registry identity. The project-specific E0 creation path receives a deterministic 16-byte AID. MicroCard also assigns deterministic registry AIDs to assemblies, which do not otherwise have a GlobalPlatform AID:

- project-specific SSD: RID `A000000151`, byte `53`, then the first ten incarnation bytes
- assembly: RID `A000000151`, byte `4C`, then the first ten signed-package digest bytes

These identifiers are registry handles. They do not change MicroCard's signed assembly identity, dependency identity or domain identifier.

## SSD lifecycle

After ISD ownership, an authenticated SCP03 session accepts INSTALL [for install and make selectable] (`E6`, P1 `0C`) for the fixed MicroCard security-domain executable. The package AID is `A0000001515350`, the module AID is `A000000151535041`, and the requested instance AID becomes the SSD's durable registry AID. The command must request Security Domain privilege `80 00 00`, use the supported default install parameters and carry an explicit empty install-token field. Duplicate AIDs and quota exhaustion fail without creating a domain.

DELETE (`E4`) accepts one `4F` AID TLV and resolves SSDs, installed instances and assemblies through the registry. The ISD cannot be deleted. SSD deletion uses the existing transactional domain deletion path, so its assemblies, instances, storage and handles are revoked in one durable state change.

Persisted domains now require a canonical, unique registry AID. Snapshots from before this field was introduced fail closed. There is no conversion or upgrade path.

## Assembly transfer and installation

GlobalPlatform Card Specification 2.3.1, §11.6.1 leaves the runtime representation open: “The runtime environment internal handling or storage of the Load File is beyond the scope of this Specification.” MicroCard therefore defines one proprietary Load File Data Block format while retaining the standard command framing.

INSTALL [for load] (`E6`, P1 `02`) carries the standard LV fields from §11.5.2.3.1. The Load File AID is `A0000001514C` followed by the first ten bytes of the package SHA-256. The Security Domain AID is the durable registry AID of the target ISD or SSD. The Load File Data Block Hash is the complete 32-byte SHA-256. Load Parameters and Load Token are empty. Other hash sizes, tokens and parameters are rejected.

Sequential LOAD commands (`E8`) follow §§11.6.2.1-11.6.2.3. P2 starts at zero and increments without gaps. P1 is `00` until the final `80` block. The first block starts one canonical BER `C4` Load File Data Block whose value is the complete MP03 package. The wrapper is parsed and discarded from the first borrowed command slice, so only package bytes enter the bounded staging vector. No DAP block or ciphered `D4` block is accepted. A wrong sequence, length, hash, signature, target domain or package structure aborts staging. ISD selection, a new SCP03 initialization or a secure-channel error also clears it.

Only the final LOAD block can activate content. Activation uses the normal device verifier once, compares its SHA-256 with the INSTALL request, enforces the MP03 domain and incarnation, verifies Ed25519, links dependencies and commits signer binding, versions and package bytes transactionally.

INSTALL [for install and make selectable] (`E6`, P1 `0C`) installs a declared assembly instance when its Executable Load File AID names a loaded package. In this profile the Executable Module and Application AIDs must be the same signed lifecycle AID, privileges are zero, Install Parameters are `C9 00`, and the Install Token is empty. The exact package is resolved before its install method executes.

## Current boundary

The authenticated project-specific E2 inventory remains available for diagnostics. GlobalPlatformPro's `--load` option accepts CAP files only, so the interop test sends the profiled INSTALL [for load] and LOAD commands with repeated `--secure-apdu`. Stable release `v25.10.20` parses `--install-only` without sending a command, so the check also sends the standard installation command through `--secure-apdu`, then exercises normal `--delete` operations. This does not claim CAP compatibility. Assembly signatures, permanent signer binding, dependency verification, quotas and incarnation replay protection apply to every path.

The optional `scripts/gppro_card_data_test.py` check takes an explicitly supplied GlobalPlatformPro jar and required digest. It passes simulator Card Data into GlobalPlatformPro's parser, takes ISD ownership, creates SSD `F04D435344`, streams a differently signed Counter package through standard load commands, confirms the durable assembly and instance counts through authenticated inventory, removes the instance and assembly, deletes the SSD and confirms each removal. Durable-state assertions avoid depending on release-specific display labels. The test fails on any INSTALL or LOAD status other than `9000`.

`docs/GLOBALPLATFORMPRO_PIN.json` pins the official stable `v25.10.20` release artifact, tag object, source commit, size, SHA-256 and reproducible-build manifest fields. `scripts/verify_gppro_pin.py` checks a separately downloaded ignored jar against that record without network access. The artifact remains outside version control. The earlier source-build result at commit `b9765231d17182bd1b72a2a3983a58ef17a43f84`, jar SHA-256 `cccb0dbe045d9d65a10c30cef0a1452f035be106cb7e367509531bf188b0d700`, remains historical evidence only.
