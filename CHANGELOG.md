# Release Notes for IP Guard

## 1.3.0 - 2026-09-25

### Added
- `IpRange::isOwnSiteOrigin()`, which only matches one of the install's own sites on its exact scheme, host and port, and never when `@web` is taken from the request.

## 1.2.0 - 2026-09-22

### Added
- A test suite covering every reserved range and every way of writing an IPv4 address inside an IPv6 one.

### Changed
- The guard may now refuse an address it used to allow. If you keep your own allowlist, check it.

### Security
- IPv4 addresses written inside IPv6 ones (hex-mapped, NAT64 and 6to4) are now checked as the IPv4 address they reach. Public addresses written this way are still allowed.

## 1.1.0 - 2026-09-18

### Added
- A `Dns` class that looks up a host without PHP warnings when the name doesn't resolve.

## 1.0.0 - 2026-09-18

### Added
- `IpRange::isPrivate()`, which refuses private, loopback, link-local, carrier-grade NAT, test, multicast and reserved addresses, IPv4 and IPv6. An address that won't parse counts as private.
- `IpRange::isOwnSiteHost()`, so an install that resolves to a private address can still reach its own sites.
