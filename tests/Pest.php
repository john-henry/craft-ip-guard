<?php

/**
 * Unit tests run without a Craft application instance; any test calling
 * Craft::$app will fail in the Unit directory. Address classification is pure
 * and belongs there. Only isOwnSiteHost() reads Craft's site config, so it is
 * the one thing that needs an application, and it lives in Integration.
 *
 * Run from the parent Craft project:
 *
 *   ddev exec composer test:ipg
 */

use markhuot\craftpest\test\RefreshesDatabase;
use markhuot\craftpest\test\TestCase;

uses(
    TestCase::class,
    RefreshesDatabase::class,
)->in('Integration');
