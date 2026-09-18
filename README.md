# IP Guard for Craft CMS

Tells a public address from one a server should never be asked to fetch.

It is the address half of an SSRF guard, and nothing else. There is no HTTP client in here, no
redirect handling, no exceptions of its own. It answers one question, and the plugin asking it
decides what to do with the answer.

## The thinking behind it

Any plugin that fetches a URL somebody else supplied needs to know whether that URL points somewhere
it has no business going: the machine it is running on, another box on the same private network, or
the cloud metadata endpoint at 169.254.169.254 that will hand out credentials to anyone who asks.

That check is a list of address ranges. The list is dull, it comes out of the RFCs, and it changes
about never. The trouble is what happens when two plugins each keep their own copy. They do not stay
the same. One picks up carrier-grade NAT and the other does not, somebody fixes a gap in the plugin
they happened to be working in, and the other one quietly keeps the hole. A guard that is right in
one place and wrong in another is worse than one that is wrong in both, because you stop checking.

So the list lives here, on its own, and the plugins read from it. A range added is a range added for
all of them.

## What it covers

For IPv4: the RFC 1918 private blocks, loopback, link-local (which is where the metadata endpoint
sits), this-network, carrier-grade NAT, the IETF protocol assignments, benchmarking, TEST-NET-1 and
the reserved class E space.

For IPv6: loopback, unspecified, unique-local and link-local.

PHP's own `FILTER_FLAG_NO_PRIV_RANGE` and `FILTER_FLAG_NO_RES_RANGE` are applied first. The explicit
list is belt and braces over them, because some builds apply those flags less completely than others.

An address that will not parse comes back as private. The caller is deciding whether to open a
connection, and the safe answer to "I cannot tell" is no.

## Using it

```php
use johnhenry\ipguard\IpRange;

if (IpRange::isPrivate($ip)) {
    // Refuse it, however your plugin refuses things.
}
```

There is a second check for the site's own hostnames:

```php
if (IpRange::isOwnSiteHost($host)) {
    // One of this install's own sites, so the range check does not apply.
}
```

That one matters more than it looks. A local or intranet install legitimately resolves to a private
address, and its own hostname comes from Craft's site config rather than from anything a visitor
typed, so it is exempt. Without that exemption the guard refuses the site it is running on.

## What it does not do

Validating an address is not the whole job. A hostname can answer with a public address when you
check it and a private one when you connect, which is DNS rebinding, and no amount of re-checking the
name closes it. Closing it means handing the addresses you validated straight to the connection and
following redirects yourself, one checked hop at a time. That belongs in the plugin doing the
fetching, and both of the ones using this package do it.

## Requirements

Craft CMS 5 and PHP 8.2 or later.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
