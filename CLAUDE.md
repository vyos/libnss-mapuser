# CLAUDE.md

## Project purpose

NSS (Name Service Switch) module that maps `getpwnam()` / `getpwuid()` lookups for arbitrary usernames onto a single named local account. Used in conjunction with `pam_radius`/TACACS+/etc. to make remote-authenticated users appear as a single configured local user without provisioning each one in `/etc/passwd`. Originally written by Cumulus Networks (Dave Olson, 2017); maintained by VyOS for VyOS images.

## Tech stack

- C; GNU `make` (single `Makefile`).
- Two NSS plugins built from this tree:
  - `libnss_mapname.so.2` (name lookup — last in nsswitch.conf chain).
  - `libnss_mapuid.so.2` (UID lookup — first in chain so mapped UIDs resolve to the mapped name).
- Manpages: `nss_mapuser.5` (config-file format), `nss_mapuser.8` (operator).
- Debian packaging under `debian/` (binary package: `vyos-libnss-mapuser`).
- Legacy Jenkinsfile present (Cumulus-era CI; not used by VyOS).

## Build / test / run

```
make
sudo make install
# Debian package
dpkg-buildpackage -uc -us -tc -b
```

Configuration: `/etc/nss_mapuser.conf` — defines the single account to which all unknown names map. Plugins are wired in `/etc/nsswitch.conf` per the README.

No automated test suite.

## Repository layout

- `map_common.[ch]` — shared mapping logic.
- `nss_mapname.c` — name-lookup plugin source.
- `nss_mapuid.c` — UID-lookup plugin source.
- `nss_mapuser.conf` — example config file.
- `nss_mapuser.5`, `nss_mapuser.8` — manpages.
- `debian/` — Debian packaging (`vyos-libnss-mapuser` binary, postinst/prerm hooks, lintian overrides, symbols).
- `Makefile`, `LICENSE` (GPL-2), `AUTHORS`, `README`, `Jenkinsfile` (legacy Cumulus CI).

## Cross-repo context

One of the §3.6 authentication libraries (`libnss-*`, `libpam-*`, `libtacplus-map`). Pre-dependency of `vyos-1x` for RADIUS/TACACS+ auth flows. Native-package category — built and shipped to `packages.vyos.net` via `VyOS-Networks/vyos-build-packages`, then consumed at ISO assembly time by `vyos/vyos-build`.

## Conventions

- Commit / PR title format: `component: T12345: description` (Phorge task ID at https://vyos.dev mandatory). Enforced by `vyos/.github` reusable workflows where consumed.
- Branch model: `current` (rolling), `circinus` (1.5 LTS), `sagitta` (1.4 LTS), `equuleus` (1.3 LTS).
- Treat as upstream-vendored — keep diffs against the Cumulus baseline minimal.

## Mirror relationship

Mirror twin: `VyOS-Networks/libnss-mapuser`. Canonical side is **here** (`vyos/libnss-mapuser`).

## Notes for future contributors

- The NSS module ordering matters — `libnss_mapuid` must be **first** and `libnss_mapname` **last** in `nsswitch.conf`. The README explains why; don't reverse them.
- `passwd` field is forced to `'x'` so PAM auth on the base account is impossible — only the mapped accounts authenticate (typically via `pam_radius`).
- License: GPL-2-or-later. Original copyright Cumulus Networks; VyOS additions (2020+) layered on top.

---

This file is mirrored on Confluence: [`vyos/libnss-mapuser`](https://internal.confluence.vyos.com/wiki/spaces/VYOS/pages/817889451). The Confluence page also carries the per-repo audit data (settings, workflows, secret counts, hygiene) that complements this CLAUDE.md. Edit either side; resync via the documentation pipeline.
