# Release Notes for IP Guard

## 1.2.0 - 2026-09-22

### Security
- The address check now reads an IPv4 address written inside an IPv6 one. There are several ways of
  writing the same address, and only one of them was being caught: `::ffff:169.254.169.254` was
  unwrapped, but `::ffff:a9fe:a9fe`, which is that exact address in hex, went through as though it were
  an ordinary public IPv6 address. The same went for the NAT64 and 6to4 forms, `64:ff9b::a9fe:a9fe` and
  `2002:a9fe:a9fe::`. On a network carrying either of those, a link could have been followed to
  somewhere on your own side of it, the cloud metadata endpoint included. The check is now made on the
  address the packet reaches rather than on how it was spelled.
- A public address carried the same way is still allowed. `2002:808:808::` is 8.8.8.8 over 6to4 and it
  is fetched as normal, because the point is to judge where a request lands, not to refuse a whole
  addressing scheme.

### Added
- A test suite. The address classification is the part of an SSRF guard that fails quietly, so every
  reserved block is now pinned, along with the addresses either side of each one and all four ways of
  writing an embedded IPv4 address.

> [!IMPORTANT]
> This widens what counts as private, so a consumer on a `^1.1` constraint picks it up on the next
> `composer update` with nothing else to do. There is no schema and no migration. If you run your own
> allowlist of addresses the guard may now refuse one it used to permit, which is the intended change,
> but worth knowing about before it surprises you.

## 1.1.0 - 2026-09-18

### Added
- A `Dns` class for looking up a host without the lookup failing being treated as a fault. A name that
  will not resolve is an ordinary answer to a guard: somebody pasted a dead link, or a name was retired.
  PHP does not see it that way and raises a warning on top of returning false. The usual answer to that
  is an `@`, which hides every other error the call could raise as well. This puts a handler up for the
  length of the call and takes it down again in a `finally`, so a throw cannot leave the rest of the
  process without its own error reporting.

## 1.0.0 - 2026-09-18

First release.

### Added
- `IpRange::isPrivate()`, which tells a public address from one that must never be fetched: the RFC 1918
  private blocks, loopback, link-local (which is where the cloud metadata endpoint sits), carrier-grade
  NAT, the test and benchmarking ranges, multicast and the reserved class E space, and the IPv6
  equivalents. An address that will not parse counts as private, because the caller is deciding whether
  to open a connection and the safe answer to "I cannot tell" is no.
- `IpRange::isOwnSiteHost()`, so an install that legitimately resolves to a private address, a local or
  intranet one, can still reach its own sites. The hostnames come from Craft's own site config rather
  than from anything a visitor typed.
