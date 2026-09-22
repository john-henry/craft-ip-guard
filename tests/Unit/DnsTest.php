<?php

use johnhenry\ipguard\Dns;

// ---------------------------------------------------------------------------
// The reason this class exists is that dns_get_record() raises a warning as
// well as returning false, and the usual fix, an @, hides every other error the
// call could raise. What has to hold is that the handler put up for the call is
// taken down again, so nothing else in the process loses its error reporting.
//
// `.invalid` is reserved by RFC 2606 and never resolves, so these need no
// network and cannot start passing because a name was registered.
// ---------------------------------------------------------------------------

const UNRESOLVABLE = 'nonexistent-host-for-tests.invalid';

describe('Dns::records()', function() {
    it('returns an empty list where the lookup fails', function() {
        expect(Dns::records(UNRESOLVABLE, DNS_A))->toBe([]);
    });

    it('puts the caller\'s error handler back afterwards', function() {
        $seen = [];

        set_error_handler(function(int $number, string $message) use (&$seen): bool {
            $seen[] = $message;

            return true;
        });

        try {
            Dns::records(UNRESOLVABLE, DNS_A);
            trigger_error('still mine', E_USER_WARNING);
        } finally {
            restore_error_handler();
        }

        // The failed lookup's own warning went to the handler Dns put up, and
        // the error raised after it came back here, which it only can if the
        // handler was restored.
        expect($seen)->toBe(['still mine']);
    });

    it('leaves no handler behind where there was none', function() {
        $before = set_error_handler(null);
        restore_error_handler();

        Dns::records(UNRESOLVABLE, DNS_A);

        $after = set_error_handler(null);
        restore_error_handler();

        expect($after)->toBe($before);
    });
});

describe('Dns::addressesFor()', function() {
    it('returns an empty list for a host that does not resolve', function() {
        expect(Dns::addressesFor(UNRESOLVABLE))->toBe([]);
    });

    it('returns an empty list for an empty host', function() {
        expect(Dns::addressesFor(''))->toBe([]);
    });

    it('falls back to a plain lookup where the record lookups come back empty', function() {
        // localhost answers gethostbyname() without needing a nameserver, which
        // is the branch that carries hosts with no A or AAAA record of their own.
        $addresses = Dns::addressesFor('localhost');

        expect($addresses)->not->toBeEmpty();

        foreach ($addresses as $address) {
            expect(filter_var($address, FILTER_VALIDATE_IP))->not->toBeFalse();
        }
    });

    it('returns each address once', function() {
        $addresses = Dns::addressesFor('localhost');

        expect($addresses)->toEqual(array_values(array_unique($addresses)));
    });
});
