<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoader;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoaderException;
use MinVWS\OpenIDConnectLaravel\Tests\TestCase;

class OpenIDConfigurationLoaderTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();

        // Support for running tests with Laravel 8
        if (method_exists(Http::class, 'preventStrayRequests')) {
            Http::preventStrayRequests();
        }
    }

    public function testConfigurationIsLoaded(): void
    {
        $this->fakeSuccessfulResponse();

        $loader = new OpenIDConfigurationLoader(
            'https://provider.rdobeheer.nl',
        );

        $configuration = $loader->getConfiguration();

        $this->assertSame("3.0", $configuration->version);
        $this->assertSame("https://provider.rdobeheer.nl", $configuration->issuer);
        $this->assertSame("https://provider.rdobeheer.nl/authorize", $configuration->authorizationEndpoint);
        $this->assertSame("https://provider.rdobeheer.nl/jwks", $configuration->jwksUri);
        $this->assertSame("https://provider.rdobeheer.nl/token", $configuration->tokenEndpoint);
        $this->assertSame("https://provider.rdobeheer.nl/userinfo", $configuration->userinfoEndpoint);
    }

    public function testConfigurationIsLoadedMultipleTimesWhenNotCached(): void
    {
        $this->fakeSuccessfulResponse();

        $loader = new OpenIDConfigurationLoader(
            'https://provider.rdobeheer.nl',
        );

        // Load 2 times
        $loader->getConfiguration();
        $configuration = $loader->getConfiguration();

        Http::assertSentCount(2);

        $this->assertSame("3.0", $configuration->version);
        $this->assertSame("https://provider.rdobeheer.nl", $configuration->issuer);
        $this->assertSame("https://provider.rdobeheer.nl/authorize", $configuration->authorizationEndpoint);
        $this->assertSame("https://provider.rdobeheer.nl/jwks", $configuration->jwksUri);
        $this->assertSame("https://provider.rdobeheer.nl/token", $configuration->tokenEndpoint);
        $this->assertSame("https://provider.rdobeheer.nl/userinfo", $configuration->userinfoEndpoint);
    }

    public function testConfigurationIsCached(): void
    {
        $this->fakeSuccessfulResponse();

        $loader = new OpenIDConfigurationLoader(
            issuer: 'https://provider.rdobeheer.nl',
            cacheStore: Cache::store('array'),
            cacheTtl: 86400,
        );

        // Load multiple times
        $loader->getConfiguration();
        $loader->getConfiguration();

        $configuration = $loader->getConfiguration();

        // Assert that the configuration is only loaded once instead of 3 times
        Http::assertSentCount(1);

        $this->assertSame("3.0", $configuration->version);
        $this->assertSame("https://provider.rdobeheer.nl", $configuration->issuer);
        $this->assertSame("https://provider.rdobeheer.nl/authorize", $configuration->authorizationEndpoint);
        $this->assertSame("https://provider.rdobeheer.nl/jwks", $configuration->jwksUri);
        $this->assertSame("https://provider.rdobeheer.nl/token", $configuration->tokenEndpoint);
        $this->assertSame("https://provider.rdobeheer.nl/userinfo", $configuration->userinfoEndpoint);
    }

    public function testLoaderThrowsExceptionWhenProviderReturns400ResponseCode(): void
    {
        $this->fakeInvalidResponse(statusCode: 400, body: ['error' => 'something']);

        $this->expectException(OpenIDConfigurationLoaderException::class);
        $this->expectExceptionMessage("Could not load OpenID configuration from issuer");

        $loader = new OpenIDConfigurationLoader(
            'https://provider.rdobeheer.nl',
        );

        $configuration = $loader->getConfiguration();
    }


    public function testLoaderThrowsExceptionWhenProviderReturns400ResponseCodeAssertContext(): void
    {
        $this->fakeInvalidResponse(statusCode: 400, body: ['error' => 'something']);

        try {
            $loader = new OpenIDConfigurationLoader(
                'https://provider.rdobeheer.nl',
            );
            $configuration = $loader->getConfiguration();
        } catch (OpenIDConfigurationLoaderException $exception) {
            $this->assertSame("Could not load OpenID configuration from issuer", $exception->getMessage());

            $context = $exception->context();
            $this->assertSame("https://provider.rdobeheer.nl", $context['issuer']);
            $this->assertSame("https://provider.rdobeheer.nl/.well-known/openid-configuration", $context['url']);
            $this->assertSame(400, $context['response_status_code']);
        }
    }

    public function testLoaderThrowsExceptionWhenProviderReturns500ResponseCodeAssertContext(): void
    {
        $this->fakeInvalidResponse(statusCode: 500, body: ['error' => 'something']);

        try {
            $loader = new OpenIDConfigurationLoader(
                'https://provider.rdobeheer.nl',
            );
            $configuration = $loader->getConfiguration();
        } catch (OpenIDConfigurationLoaderException $exception) {
            $this->assertSame("Could not load OpenID configuration from issuer", $exception->getMessage());

            $context = $exception->context();
            $this->assertSame("https://provider.rdobeheer.nl", $context['issuer']);
            $this->assertSame("https://provider.rdobeheer.nl/.well-known/openid-configuration", $context['url']);
            $this->assertSame(500, $context['response_status_code']);
        }
    }

    public function testLoaderThrowsExceptionWhenProviderReturns200ButNullResponse(): void
    {
        $this->fakeInvalidResponse(statusCode: 200, body: null);

        try {
            $loader = new OpenIDConfigurationLoader(
                'https://provider.rdobeheer.nl',
            );
            $configuration = $loader->getConfiguration();
        } catch (OpenIDConfigurationLoaderException $exception) {
            $this->assertSame("Response body of OpenID configuration is not JSON", $exception->getMessage());

            $context = $exception->context();
            $this->assertSame("https://provider.rdobeheer.nl", $context['issuer']);
            $this->assertSame("https://provider.rdobeheer.nl/.well-known/openid-configuration", $context['url']);
            $this->assertSame(200, $context['response_status_code']);
            $this->assertSame('', $context['response_body']);
        }
    }

    public function testLoaderThrowsExceptionWhenProviderReturns200ButStringResponse(): void
    {
        $this->fakeInvalidResponse(statusCode: 200, body: 'some invalid response');

        try {
            $loader = new OpenIDConfigurationLoader(
                'https://provider.rdobeheer.nl',
            );
            $configuration = $loader->getConfiguration();
        } catch (OpenIDConfigurationLoaderException $exception) {
            $this->assertSame("Response body of OpenID configuration is not JSON", $exception->getMessage());

            $context = $exception->context();
            $this->assertSame("https://provider.rdobeheer.nl", $context['issuer']);
            $this->assertSame("https://provider.rdobeheer.nl/.well-known/openid-configuration", $context['url']);
            $this->assertSame(200, $context['response_status_code']);
            $this->assertSame('some invalid response', $context['response_body']);
        }
    }


    public function testLoaderReturnsEmptyConfigurationOnEmptyJsonResponse(): void
    {
        $this->fakeInvalidResponse(statusCode: 200, body: []);


        $loader = new OpenIDConfigurationLoader(
            'https://provider.rdobeheer.nl',
        );
        $configuration = $loader->getConfiguration();

        $this->assertEmpty($configuration->version);
        $this->assertEmpty($configuration->issuer);
        $this->assertEmpty($configuration->authorizationEndpoint);
        $this->assertEmpty($configuration->jwksUri);
        $this->assertEmpty($configuration->tokenEndpoint);
    }

    protected function fakeSuccessfulResponse(): void
    {
        Http::fake([
            'https://provider.rdobeheer.nl/*' => Http::response([
                "version" => "3.0",
                "token_endpoint_auth_methods_supported" => [
                    "none"
                ],
                "claims_parameter_supported" => true,
                "request_parameter_supported" => false,
                "request_uri_parameter_supported" => true,
                "require_request_uri_registration" => false,
                "grant_types_supported" => [
                    "authorization_code"
                ],
                "frontchannel_logout_supported" => false,
                "frontchannel_logout_session_supported" => false,
                "backchannel_logout_supported" => false,
                "backchannel_logout_session_supported" => false,
                "issuer" => "https://provider.rdobeheer.nl",
                "authorization_endpoint" => "https://provider.rdobeheer.nl/authorize",
                "jwks_uri" => "https://provider.rdobeheer.nl/jwks",
                "token_endpoint" => "https://provider.rdobeheer.nl/token",
                "scopes_supported" => [
                    "openid"
                ],
                "response_types_supported" => [
                    "code"
                ],
                "response_modes_supported" => [
                    "query"
                ],
                "subject_types_supported" => [
                    "pairwise"
                ],
                "userinfo_endpoint" => "https://provider.rdobeheer.nl/userinfo",
                "id_token_signing_alg_values_supported" => [
                    "RS256"
                ],
                "code_challenge_methods_supported" => [
                    "S256"
                ]
            ])
        ]);
    }

    protected function fakeInvalidResponse(int $statusCode, array|null|string $body): void
    {
        Http::fake([
            'https://provider.rdobeheer.nl/*' => Http::response($body, $statusCode),
        ]);
    }
}
