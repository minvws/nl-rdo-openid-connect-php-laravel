<?php

declare(strict_types=1);

namespace Http\Controllers;

use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfiguration;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoader;
use MinVWS\OpenIDConnectLaravel\Tests\TestCase;
use Mockery;

class LoginControllerResponseTest extends TestCase
{
    /**
     * Prevent HTTP requests from being made during tests.
     * If any HTTP requests are made during tests, an exception will be thrown.
     * This is to prevent HTTP requests from being made to the OpenID Connect provider.
     *
     * To test on Laravel 8 we need to check if the method exists.
     */
    public function setUp(): void
    {
        parent::setUp();

        if (method_exists(Http::class, 'preventStrayRequests')) {
            Http::preventStrayRequests();
        }
    }

    /**
     * Reset $_REQUEST after each test for getRoute function.
     */
    protected function tearDown(): void
    {
        $_REQUEST = [];

        parent::tearDown();
    }

    public function testLoginRouteHandlesQueryErrorParameter(): void
    {
        $this->mockOpenIDConfigurationLoader();

        config()->set('oidc.client_id', 'test-client-id');

        $response = $this->getRoute('oidc.login', ['error' => 'test-error']);

        $response
            ->assertStatus(400);
    }


    protected function mockOpenIDConfigurationLoader(): void
    {
        $mock = Mockery::mock(OpenIDConfigurationLoader::class);
        $mock
            ->shouldReceive('getConfiguration')
            ->andReturn($this->exampleOpenIDConfiguration());

        $this->app->instance(OpenIDConfigurationLoader::class, $mock);
    }

    protected function exampleOpenIDConfiguration(): OpenIDConfiguration
    {
        return new OpenIDConfiguration(
            version: "3.0",
            tokenEndpointAuthMethodsSupported: ["none"],
            claimsParameterSupported: true,
            requestParameterSupported: false,
            requestUriParameterSupported: true,
            requireRequestUriRegistration: false,
            grantTypesSupported: ["authorization_code"],
            frontchannelLogoutSupported: false,
            frontchannelLogoutSessionSupported: false,
            backchannelLogoutSupported: false,
            backchannelLogoutSessionSupported: false,
            issuer: "https://provider.rdobeheer.nl",
            authorizationEndpoint: "https://provider.rdobeheer.nl/authorize",
            jwksUri: "https://provider.rdobeheer.nl/jwks",
            tokenEndpoint: "https://provider.rdobeheer.nl/token",
            scopesSupported: ["openid"],
            responseTypesSupported: ["code"],
            responseModesSupported: ["query"],
            subjectTypesSupported: ["pairwise"],
            idTokenSigningAlgValuesSupported: ["RS256"],
            userinfoEndpoint: "https://provider.rdobeheer.nl/userinfo",
            codeChallengeMethodsSupported: ["S256"],
        );
    }

    /**
     * Override the Laravel GET request to put the query parameters in $_REQUEST.
     * This is to test the functionality because the tests in Laravel only sets
     * $_POST and $_GET and OpenIDConnectClient uses $_REQUEST.
     *
     * @param string $routeName
     * @param array<string, string> $queryParams
     * @return TestResponse
     */
    protected function getRoute(string $routeName, array $queryParams = []): TestResponse
    {
        $_REQUEST = [];
        foreach ($queryParams as $key => $value) {
            $_REQUEST[$key] = $value;
        }
        return $this->get(route($routeName, $queryParams));
    }
}
