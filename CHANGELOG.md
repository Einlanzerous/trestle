# Changelog

## [0.3.0](https://github.com/Einlanzerous/trestle/compare/v0.2.0...v0.3.0) (2026-11-15)


### Features

* **quota:** per-token quotas via TRESTLE_QUOTA_BYTES_BY_TOKEN (GENZO-50) ([#11](https://github.com/Einlanzerous/trestle/issues/11)) ([3c2452d](https://github.com/Einlanzerous/trestle/commit/3c2452d0d7a3ad72bc85f8221d376ff360b2d73d))
* **sniff:** QuickTime without ftyp, and 3GP (GENZO-26) ([#8](https://github.com/Einlanzerous/trestle/issues/8)) ([d179f0a](https://github.com/Einlanzerous/trestle/commit/d179f0a6441c09bacdc08f882bae54e131146bc0))


### Bug Fixes

* **storage:** fsync directories after blob and record renames (GENZO-30) ([#10](https://github.com/Einlanzerous/trestle/issues/10)) ([a892731](https://github.com/Einlanzerous/trestle/commit/a892731a6ea3ac542b5075ee1a4064fa6e43b621))

## [0.2.0](https://github.com/Einlanzerous/trestle/compare/v0.1.0...v0.2.0) (2026-11-14)


### Features

* **api:** authenticated blob read (GENZO-6) ([#5](https://github.com/Einlanzerous/trestle/issues/5)) ([a407d7e](https://github.com/Einlanzerous/trestle/commit/a407d7e16db1e8e535ac098601b488e11c2679f5))
* **serve:** TRESTLE_PUBLIC_SERVE switch for a private instance (GENZO-5) ([#4](https://github.com/Einlanzerous/trestle/issues/4)) ([01381ec](https://github.com/Einlanzerous/trestle/commit/01381ec122b8d3e477ec31ed128b4802ab379360))
* **sniff:** TRESTLE_ALLOWED_TYPES with HEIC/HEIF, AVIF and QuickTime (GENZO-7) ([#6](https://github.com/Einlanzerous/trestle/issues/6)) ([dd731df](https://github.com/Einlanzerous/trestle/commit/dd731df7eab03515ad7662e04637a938c8d17897))

## 0.1.0 (2026-09-24)


### Features

* **service:** SERV-205 — content-addressed upload and public serve path ([d3e91a4](https://github.com/Einlanzerous/trestle/commit/d3e91a40bfa5bd4e03fae8f2d0dedf3587742a74))


### Bug Fixes

* **service:** data-dir lock, boot reconcile, and review nits (SERV-205) ([#3](https://github.com/Einlanzerous/trestle/issues/3)) ([9350d04](https://github.com/Einlanzerous/trestle/commit/9350d046491caf81e1a2c0e8751bb944937eaca3))


### Maintenance

* SERV-134 — scaffold Trestle with the design of record ([98c01ab](https://github.com/Einlanzerous/trestle/commit/98c01ab694ca516a392b254081ce3e91a6edfb98))
