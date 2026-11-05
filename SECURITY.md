# Security policy

HotspotShade is a prototype. Please report security problems privately and do
not open a public issue for them.

Use GitHub's private vulnerability reporting for this repository (Security tab,
"Report a vulnerability"). Include the affected platform, the version or commit,
and steps to reproduce. Do not include real tokens, identity keys, or
captures of personal traffic.

Areas of most interest:

- The pairing protocol and the source device token.
- The privileged helper and the engine control channel on each desktop.
- Route, rule, and adapter cleanup, and any way to leave traffic outside the
  tunnel without a warning.
- The local control page and its bearer secret.
