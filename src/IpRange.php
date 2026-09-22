<?php

/**
 * @copyright Copyright (c) John Henry Donovan
 */

namespace johnhenry\ipguard;

use Craft;

/**
 * Tells a public address from one that must never be fetched.
 *
 * The address half of an SSRF guard, shared by every plugin that fetches a URL
 * somebody else supplied. Each plugin keeps its own guard around this: what it
 * does with an unsafe address, how it resolves a name, and how it follows a
 * redirect are its own business. What counts as unsafe is not, and a range
 * missed in one copy and not the other is exactly the bug this exists to stop.
 *
 * @author John Henry Donovan <info@johnhenry.ie>
 * @since 1.0.0
 */
class IpRange
{
    // Const Properties
    // =========================================================================

    /**
     * @var array<int, array{0: string, 1: int}> Reserved IPv4 blocks, as a
     *      network address and a prefix length.
     *
     * Belt and braces over PHP's own filter, which some builds apply less
     * completely than others. Covers the RFC 1918 private blocks, loopback,
     * link-local (which carries the cloud metadata endpoint at 169.254.169.254),
     * "this network", carrier-grade NAT, IETF protocol assignments, benchmarking,
     * TEST-NET-1 and the reserved class E space.
     */
    private const RESERVED_IPV4 = [
        ['10.0.0.0', 8],
        ['172.16.0.0', 12],
        ['192.168.0.0', 16],
        ['127.0.0.0', 8],
        ['169.254.0.0', 16],
        ['0.0.0.0', 8],
        ['100.64.0.0', 10],
        ['192.0.0.0', 24],
        ['198.18.0.0', 15],
        ['192.0.2.0', 24],
        ['198.51.100.0', 24],
        ['203.0.113.0', 24],
        ['192.88.99.0', 24],
        ['224.0.0.0', 4],
        ['240.0.0.0', 4],
    ];

    /**
     * @var string[] IPv6 prefixes that are loopback, unspecified, unique-local
     *      or link-local.
     */
    private const RESERVED_IPV6_PREFIXES = ['fc', 'fd', 'fe8', 'fe9', 'fea', 'feb', 'ff'];

    /**
     * @var array<int, array{0: string, 1: int}> The IPv6 blocks that carry an
     * IPv4 address inside them, as a packed prefix and the byte offset the
     * address sits at.
     *
     * Matched on the packed bytes rather than the text, because the same
     * address has several spellings and only one of them used to be caught:
     * `::ffff:127.0.0.1` was unwrapped and `::ffff:7f00:1`, which is the same
     * address, was not.
     */
    private const IPV4_IN_IPV6 = [
        // ::ffff:0:0/96, IPv4-mapped.
        ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12],
        // 64:ff9b::/96, NAT64 (RFC 6052).
        ["\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00", 12],
        // 2002::/16, 6to4 (RFC 3056), where it sits in the next four bytes.
        ["\x20\x02", 2],
    ];

    // Public Methods
    // =========================================================================

    /**
     * Whether an address is private, loopback, link-local or otherwise reserved.
     *
     * An address that will not parse counts as private: the caller is deciding
     * whether to open a connection, and the safe answer to "I cannot tell" is
     * no.
     *
     * @param string $ip The address to test.
     * @return bool True where the address must not be fetched.
     *
     * @author John Henry Donovan <info@johnhenry.ie>
     * @since 1.0.0
     */
    public static function isPrivate(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
        }

        // An IPv6 address can carry an IPv4 one inside it, and the ranges
        // below only know about IPv4. Unwrapped first so that 64:ff9b::a9fe:a9fe
        // is judged as 169.254.169.254, which is what it reaches.
        $embedded = self::_embeddedIpv4($ip);

        if ($embedded !== null) {
            $ip = $embedded;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }

        return self::_isInReservedRange($ip);
    }

    /**
     * Whether a hostname is one this install actually serves.
     *
     * A site's own hostname comes from Craft's site config rather than from
     * user input, and a local or intranet install legitimately resolves to a
     * private address, so its own hosts are exempt from the range check.
     *
     * @param string $host The hostname to test.
     * @return bool True where the host is one of this install's sites.
     *
     * @author John Henry Donovan <info@johnhenry.ie>
     * @since 1.0.0
     */
    public static function isOwnSiteHost(string $host): bool
    {
        $host = strtolower(trim($host));

        if ($host === '') {
            return false;
        }

        foreach (Craft::$app->getSites()->getAllSites() as $site) {
            $siteHost = parse_url((string)$site->getBaseUrl(), PHP_URL_HOST);

            if (is_string($siteHost) && strtolower($siteHost) === $host) {
                return true;
            }
        }

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * The IPv4 address carried inside an IPv6 one, where there is one.
     *
     * @param string $ip The address to unwrap, already known to parse.
     * @return string|null The embedded IPv4 address, or null where there is
     *                     none.
     *
     * @author John Henry Donovan <info@johnhenry.ie>
     * @since 1.2.0
     */
    private static function _embeddedIpv4(string $ip): ?string
    {
        $packed = inet_pton($ip);

        if ($packed === false || strlen($packed) !== 16) {
            return null;
        }

        foreach (self::IPV4_IN_IPV6 as [$prefix, $offset]) {
            if (!str_starts_with($packed, $prefix)) {
                continue;
            }

            $address = inet_ntop(substr($packed, $offset, 4));

            return $address === false ? null : $address;
        }

        return null;
    }

    /**
     * Whether an address falls inside one of the reserved blocks named above.
     *
     * @param string $ip The address to test, already known to parse.
     * @return bool True where the address is reserved.
     *
     * @author John Henry Donovan <info@johnhenry.ie>
     * @since 1.0.0
     */
    private static function _isInReservedRange(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $long = ip2long($ip);

            if ($long === false) {
                return true;
            }

            foreach (self::RESERVED_IPV4 as [$subnet, $mask]) {
                $subnetLong = ip2long($subnet);
                $maskLong = -1 << (32 - $mask);

                if (($long & $maskLong) === ($subnetLong & $maskLong)) {
                    return true;
                }
            }

            return false;
        }

        $normalised = strtolower($ip);

        if ($normalised === '::1' || $normalised === '::') {
            return true;
        }

        foreach (self::RESERVED_IPV6_PREFIXES as $prefix) {
            if (str_starts_with($normalised, $prefix)) {
                return true;
            }
        }

        return false;
    }
}
