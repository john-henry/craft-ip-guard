<?php

/**
 * @copyright Copyright (c) John Henry Donovan
 */

namespace johnhenry\ipguard;

/**
 * Name lookups for a guard that has to survive them failing.
 *
 * A host that will not resolve is an ordinary answer to an SSRF guard, not a
 * fault: somebody pasted a dead link, or a name was retired. PHP does not see it
 * that way, and `dns_get_record()` raises a warning as well as returning false.
 *
 * Suppressing that with `@` is the usual answer and the wrong one. It hides
 * every other error the call could raise, and on a site with a strict error
 * handler it does not always hide the one you meant. The handler here is put up
 * for the length of the call only and taken down in a `finally`, so a throw
 * cannot leave the rest of the process without its own error reporting.
 *
 * @author JohnHenry <info@johnhenry.ie>
 * @since 1.1.0
 */
class Dns
{
    // Public Methods
    // =========================================================================

    /**
     * The records of one type for a host, or an empty list where the lookup
     * fails.
     *
     * @param string $host The hostname to look up.
     * @param int $type The `DNS_*` record type.
     * @return array<int, array<string, mixed>> The records, empty on failure.
     *
     * @author JohnHenry <info@johnhenry.ie>
     * @since 1.1.0
     */
    public static function records(string $host, int $type): array
    {
        set_error_handler(static fn(): bool => true);

        try {
            $records = dns_get_record($host, $type);
        } finally {
            restore_error_handler();
        }

        return is_array($records) ? $records : [];
    }

    /**
     * Every IPv4 and IPv6 address a host maps to.
     *
     * Falls back to `gethostbyname()` where the record lookups come back empty,
     * which happens on hosts that answer a plain lookup but not a record one.
     *
     * @param string $host The hostname to resolve, brackets already stripped.
     * @return string[] The addresses, empty where nothing resolved.
     *
     * @author JohnHenry <info@johnhenry.ie>
     * @since 1.1.0
     */
    public static function addressesFor(string $host): array
    {
        $ips = [];

        foreach (self::records($host, DNS_A) as $record) {
            if (!empty($record['ip'])) {
                $ips[] = $record['ip'];
            }
        }

        foreach (self::records($host, DNS_AAAA) as $record) {
            if (!empty($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        if ($ips === []) {
            $resolved = gethostbyname($host);

            if ($resolved !== $host && filter_var($resolved, FILTER_VALIDATE_IP)) {
                $ips[] = $resolved;
            }
        }

        return array_values(array_unique($ips));
    }
}
