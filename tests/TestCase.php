<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests;

use MinVWS\OpenIDConnectLaravel\OpenIDConnectServiceProvider;

class TestCase extends \Orchestra\Testbench\TestCase
{
    public function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app)
    {
        return [
            OpenIDConnectServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // perform environment setup
    }
}
