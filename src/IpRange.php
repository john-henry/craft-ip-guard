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
 * @author JohnHenry <info@johnhenry.ie>
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
        ['240.0.0.0', 4],
    ];

    /**
     * @var string[] IPv6 prefixes that are loopback, unspecified, unique-local
     *      or link-local.
     */
    private const RESERVED_IPV6_PREFIXES = ['fc', 'fd', 'fe8', 'fe9', 'fea', 'feb'];

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
     * @author JohnHenry <info@johnhenry.ie>
     * @since 1.0.0
     */
    public static function isPrivate(string $ip): bool
    {
        // Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254) so
        // the check below applies to the embedded IPv4 address.
        if (stripos($ip, '::ffff:') === 0) {
            $mapped = substr($ip, 7);
            if (filter_var($mapped, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip = $mapped;
            }
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
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
     * @author JohnHenry <info@johnhenry.ie>
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
     * Whether an address falls inside one of the reserved blocks named above.
     *
     * @param string $ip The address to test, already known to parse.
     * @return bool True where the address is reserved.
     *
     * @author JohnHenry <info@johnhenry.ie>
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
