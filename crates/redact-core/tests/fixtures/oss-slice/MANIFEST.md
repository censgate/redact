# Vendored OSS slice (GENERIC_SECRET SLO)

Hermetic, licence-clean source used by `oss_slice.rs`.
**Do not vendor `git/git` (GPL).** Blocking CI must not clone remotes.

| Project | Upstream | Pinned SHA | Licence | Lines (approx.) |
|---------|----------|------------|---------|-----------------|
| react | facebook/react `v19.1.0` | `4a9df08157f001c01b078d259748512211233dcf` | MIT | see `manifest.json` |
| redis | redis/redis `7.2.4` | `d2c8a4b91e8c0e6aefd1f5bc0bf582cddbe046b7` | BSD-3-Clause | see `manifest.json` |
| flask | pallets/flask `3.1.1` | `7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1` | BSD-3-Clause | see `manifest.json` |
| clap | clap-rs/clap `v4.5.32` | `352e99f59e7aabf2a34e5e9fd334e568a0b197e6` | MIT OR Apache-2.0 | see `manifest.json` |

Redis is pinned to **7.2.4** (BSD-3-Clause). Redis 7.4+ is RSALv2/SSPLv1 and must not be vendored here.

File lists and exact line counts: [`manifest.json`](manifest.json).
Reviewed GENERIC_SECRET fingerprints: [`reviewed.json`](reviewed.json).
