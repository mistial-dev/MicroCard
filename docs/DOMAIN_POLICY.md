# SSD capability and resource policy

The ISD may restrict an empty, unbound SSD through authenticated SCP03 command E1. Policy configuration cannot grant new native services: every capability must also exist in the firmware allowlist and package preprocessing rules. The policy becomes immutable when the SSD's first package successfully binds its signing key. Deleting and recreating the SSD is the only way to replace a bound policy.

The policy bounds native capability IDs, assembly identities and their retained version history, installed assembly instances, Int32 records, byte records and their aggregate bytes, persistent framework key slots, and active signed-package bytes. A policy may allow at most eight active assemblies and eight installed instances. Card-wide limits allow eight SSDs and sixteen installed instances, so an SSD policy can only reduce access. Execution arena, stack, frame and instruction limits remain fixed by profile v1.

Package activation checks the capability subset and assembly/package quotas before signer binding. Assembly-instance installation and every persistent mutation enforce the live policy. Startup validates the policy and all recovered packages, instances, records, and keys against it. A policy violation in persisted state fails closed.

The canonical encoding omits a default policy. Production provisioning should explicitly set a least-privilege policy before first load. Older persistent state is unsupported. Here is no conversion or upgrade route.
