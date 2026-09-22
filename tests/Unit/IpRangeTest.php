<?php

use johnhenry\ipguard\IpRange;

// ---------------------------------------------------------------------------
// This is the whole of the address half of an SSRF guard, so a gap here is a
// gap in every plugin that fetches a URL somebody else supplied. The cases are
// written as "what must never be fetched" and "what must still be reachable",
// because a guard that blocks everything passes the first half on its own.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

describe('IpRange::isPrivate(): IPv4 reserved space', function() {
    it('blocks the RFC 1918 private blocks', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        '10.0.0.1',
        '10.255.255.255',
        '172.16.0.1',
        '172.31.255.255',
        '192.168.0.1',
        '192.168.255.255',
    ]);

    it('blocks loopback', function() {
        expect(IpRange::isPrivate('127.0.0.1'))->toBeTrue();
        expect(IpRange::isPrivate('127.255.255.254'))->toBeTrue();
    });

    it('blocks the cloud metadata endpoint', function() {
        // 169.254.169.254 is the reason this class exists on a hosted install:
        // reaching it hands back instance credentials.
        expect(IpRange::isPrivate('169.254.169.254'))->toBeTrue();
    });

    it('blocks the other reserved blocks', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        '0.0.0.0',          // "this network"
        '100.64.0.1',       // carrier-grade NAT
        '192.0.0.1',        // IETF protocol assignments
        '198.18.0.1',       // benchmarking
        '192.0.2.1',        // TEST-NET-1
        '198.51.100.1',     // TEST-NET-2
        '203.0.113.1',      // TEST-NET-3
        '192.88.99.1',      // 6to4 relay anycast
        '224.0.0.1',        // multicast
        '240.0.0.1',        // class E
        '255.255.255.255',  // broadcast
    ]);
});

describe('IpRange::isPrivate(): IPv4 public space', function() {
    it('allows ordinary public addresses', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeFalse();
    })->with([
        '8.8.8.8',
        '1.1.1.1',
        '93.184.216.34',
    ]);

    it('allows the addresses either side of a reserved block', function(string $ip) {
        // A prefix length applied one bit out swallows twice the space it
        // should, or half. These are the addresses that would move.
        expect(IpRange::isPrivate($ip))->toBeFalse();
    })->with([
        '9.255.255.255',    // below 10.0.0.0/8
        '11.0.0.0',         // above 10.0.0.0/8
        '172.15.255.255',   // below 172.16.0.0/12
        '172.32.0.0',       // above 172.16.0.0/12
        '192.167.255.255',  // below 192.168.0.0/16
        '192.169.0.0',      // above 192.168.0.0/16
        '100.63.255.255',   // below 100.64.0.0/10
        '100.128.0.0',      // above 100.64.0.0/10
        '169.253.255.255',  // below 169.254.0.0/16
        '169.255.0.0',      // above 169.254.0.0/16
    ]);
});

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

describe('IpRange::isPrivate(): IPv6 reserved space', function() {
    it('blocks loopback and unspecified', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        '::1',
        '::',
        '0:0:0:0:0:0:0:1',  // the same address written out in full
    ]);

    it('blocks unique-local, link-local and multicast', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        'fc00::1',
        'fd00::1',
        'fe80::1',
        'ff02::1',
        'FE80::1',  // case is not the caller's to get right
    ]);
});

describe('IpRange::isPrivate(): IPv6 public space', function() {
    it('allows ordinary public addresses', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeFalse();
    })->with([
        '2001:4860:4860::8888',
        '2606:4700:4700::1111',
    ]);
});

// ---------------------------------------------------------------------------
// IPv4 carried inside IPv6
//
// The same address has several spellings, and a guard that reads only one of
// them is a guard with a way round it. Each block below is the same address,
// 169.254.169.254, wearing a different coat.
// ---------------------------------------------------------------------------

describe('IpRange::isPrivate(): embedded IPv4', function() {
    it('blocks the metadata endpoint however it is written', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        '::ffff:169.254.169.254',  // IPv4-mapped, dotted
        '::ffff:a9fe:a9fe',        // IPv4-mapped, hex
        '64:ff9b::a9fe:a9fe',      // NAT64, RFC 6052
        '64:ff9b::169.254.169.254',
        '2002:a9fe:a9fe::',        // 6to4, RFC 3056
    ]);

    it('blocks loopback however it is written', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        '::ffff:127.0.0.1',
        '::ffff:7f00:1',
        '64:ff9b::7f00:1',
        '2002:7f00:1::',
    ]);

    it('blocks an embedded RFC 1918 address', function(string $ip) {
        expect(IpRange::isPrivate($ip))->toBeTrue();
    })->with([
        '::ffff:10.0.0.1',
        '::ffff:a00:1',
        '64:ff9b::a00:1',
        '2002:a00:1::',
        '2002:c0a8:1::',  // 192.168.0.1
    ]);

    it('still allows a public address carried the same way', function(string $ip) {
        // Unwrapping has to judge the address reached, not the wrapper. A guard
        // that blocks every 6to4 or NAT64 address blocks legitimate traffic on
        // networks that use them.
        expect(IpRange::isPrivate($ip))->toBeFalse();
    })->with([
        '::ffff:8.8.8.8',
        '::ffff:808:808',
        '64:ff9b::808:808',
        '2002:808:808::',
    ]);
});

// ---------------------------------------------------------------------------
// Anything that will not parse
// ---------------------------------------------------------------------------

describe('IpRange::isPrivate(): unparseable input', function() {
    it('treats anything it cannot read as unsafe', function(string $input) {
        // The caller is deciding whether to open a connection. "I cannot tell"
        // has to answer no.
        expect(IpRange::isPrivate($input))->toBeTrue();
    })->with([
        '',
        ' ',
        'not-an-ip',
        'example.com',
        '999.999.999.999',
        '8.8.8',
        '8.8.8.8.8',
        ' 8.8.8.8',
        '8.8.8.8 ',
        '::ffff:999.999.999.999',
        "8.8.8.8\n",
        '0x08080808',
        '2130706433',  // 127.0.0.1 as a decimal integer
    ]);
});
