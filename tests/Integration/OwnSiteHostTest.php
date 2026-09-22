<?php

use johnhenry\ipguard\IpRange;

// ---------------------------------------------------------------------------
// A site's own hostname comes from Craft's config rather than from user input,
// and a local or intranet install legitimately resolves to a private address,
// so its own hosts are exempt from the range check. That exemption is the one
// place the guard is deliberately opened, so it has to open no wider than the
// hosts this install actually serves.
// ---------------------------------------------------------------------------

/**
 * The hostnames this install serves, taken from Craft's own site config.
 */
function configuredSiteHosts(): array
{
    $hosts = [];

    foreach (Craft::$app->getSites()->getAllSites() as $site) {
        $host = parse_url((string)$site->getBaseUrl(), PHP_URL_HOST);

        if (is_string($host) && $host !== '') {
            $hosts[] = $host;
        }
    }

    return array_values(array_unique($hosts));
}

describe('IpRange::isOwnSiteHost()', function() {
    it('recognises every host this install serves', function() {
        $hosts = configuredSiteHosts();

        expect($hosts)->not->toBeEmpty(
            'No site has a resolvable base URL, so this test proves nothing.'
        );

        foreach ($hosts as $host) {
            expect(IpRange::isOwnSiteHost($host))->toBeTrue($host);
        }
    });

    it('ignores case and surrounding whitespace', function() {
        $host = configuredSiteHosts()[0];

        expect(IpRange::isOwnSiteHost(strtoupper($host)))->toBeTrue();
        expect(IpRange::isOwnSiteHost('  ' . $host . '  '))->toBeTrue();
    });

    it('refuses a host this install does not serve', function(string $host) {
        expect(IpRange::isOwnSiteHost($host))->toBeFalse();
    })->with([
        'example.invalid',
        'localhost',
        '169.254.169.254',
        'evil.test',
    ]);

    it('refuses an empty host', function(string $host) {
        expect(IpRange::isOwnSiteHost($host))->toBeFalse();
    })->with([
        '',
        '   ',
    ]);

    it('refuses a host that merely ends with a site host', function() {
        // A suffix match here would let attacker-controlled
        // "craft-5-boilerplate.ddev.site.evil.test" through, and a prefix match
        // would let "craft-5-boilerplate.ddev.site.evil.test" through the other
        // way round. The comparison has to be the whole host.
        $host = configuredSiteHosts()[0];

        expect(IpRange::isOwnSiteHost($host . '.evil.test'))->toBeFalse();
        expect(IpRange::isOwnSiteHost('evil.test.' . $host . '.evil.test'))->toBeFalse();
        expect(IpRange::isOwnSiteHost('not-' . $host))->toBeFalse();
    });
});
