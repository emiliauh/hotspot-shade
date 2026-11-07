# Experiments

This directory holds isolated experiments. Nothing here is built by the engine,
the apps, or CI, and nothing here is production code.

Each experiment has its own manifest and lockfile. It must stay test-only, use
loopback or mocks, and state what it does not prove.

- `tls-transport-spike/`: TLS 1.3 pinned mutual authentication and byte-exact
  loopback relay. Test-only. See its `README.md` and `INTEROP.md`.
