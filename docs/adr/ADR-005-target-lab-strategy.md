# ADR-005: Target and Lab Strategy

Status: accepted

Historical source: [`ADRS- PRD/PAM-MVP-ADR-005-Target-Lab-Strategy.docx`](../../ADRS-%20PRD/PAM-MVP-ADR-005-Target-Lab-Strategy.docx)

## Context

The broker must be exercised against a real SSH server on a separate trust
boundary without making a VM manager part of the application. The historical
decision references T04, T06, and deferred host compromise D01.

## Decision

- Use a separate Debian Linux guest under QEMU/KVM and libvirt as the tested
  lab target.
- Run OpenSSH and a dedicated privileged-account example (`pamadmin`).
- Configure the target IP/port, account reference, and independently verified
  ED25519 SHA256 host fingerprint in the PAM runtime.
- Reject a host-key mismatch before target password authentication.
- Apply a Paramiko 5.0.0 policy that disables CBC/3DES ciphers,
  SHA-1/MD5 MACs, and `ssh-rsa` for host/public-key signatures. The remaining
  enabled policy uses AES CTR/GCM, SHA-2 MACs, Ed25519/ECDSA/RSA-SHA2 host
  keys, and Paramiko's SHA-2/Curve25519/ECDH key exchanges.
- Keep VM creation/control, libvirt, snapshots, and network configuration out
  of the application/domain.
- Support manual installation; infrastructure-as-code is not required for the
  MVP.

## Current implementation note

The successful environment used Debian 13, libvirt's default NAT network, host
`192.168.122.227`, and a pinned fingerprint recorded by the provisioning
defaults. These are tested examples, not portable universal values. Another
engineer must discover their guest address, verify their fingerprint out of
band, and pass both non-secret values to the provisioning tool as documented
in [Lab Setup](../LAB_SETUP.md).

The historical ADR named `HOST_KEY_MISMATCH` as desirable audit evidence. The
current broker correctly denies the connection before authentication, but the
production audit contract records broker-open failures generically as
`SESSION_FAILED`/`broker_open_failed`. That event-scope difference is recorded
in [ADR-004](ADR-004-audit-integrity.md); it is not hidden or represented as
already implemented.

If a server and client share no enabled algorithm, Paramiko negotiation fails
through the existing secret-free SSH connection error and closes the transport
and socket. There is no permissive retry or fallback policy.

## Consequences

The real target proves integration that fakes cannot, while automated tests
still replace the network boundary and remain deterministic. Live evidence is
environment-specific and operator-run. Docker is neither required nor part of
the application architecture.
