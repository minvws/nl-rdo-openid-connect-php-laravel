<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Feature\Http\Controllers;

use Illuminate\Support\Facades\Http;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfiguration;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoader;
use MinVWS\OpenIDConnectLaravel\OpenIDConnectClient;
use MinVWS\OpenIDConnectLaravel\Tests\TestCase;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;

class LoginControllerTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();

        // Support for running tests with Laravel 8
        if (method_exists(Http::class, 'preventStrayRequests')) {
            Http::preventStrayRequests();
        }
    }

    public function testLoginRouteRedirectsToAuthorizeUrlOfProvider(): void
    {
        $this->mockOpenIDConfigurationLoader();

        config()->set('oidc.client_id', 'test-client-id');

        $response = $this->get(route('oidc.login'));
        $response
            ->assertStatus(302)
            ->assertRedirectContains("https://provider.rdobeheer.nl/authorize")
            ->assertRedirectContains('response_type=code')
            ->assertRedirectContains('redirect_uri=http%3A%2F%2Flocalhost%2Foidc%2Flogin')
            ->assertRedirectContains('client_id=test-client-id')
            ->assertRedirectContains('scope=openid')
            ->assertRedirectContains('code_challenge_method=S256');
    }

    #[DataProvider('scopesProvider')]
    public function testLoginRouteRedirectsToAuthorizeUrlOfProviderWithScopes(
        array $additionalScopes,
        string $scopeInUrl
    ): void {
        $this->mockOpenIDConfigurationLoader();

        config()->set('oidc.client_id', 'test-client-id');
        config()->set('oidc.additional_scopes', $additionalScopes);

        $response = $this->get(route('oidc.login', ['login_hint' => 'test-login-hint']));
        $response
            ->assertStatus(302)
            ->assertRedirectContains("https://provider.rdobeheer.nl/authorize")
            ->assertRedirectContains('test-client-id')
            ->assertRedirectContains('login_hint=test-login-hint')
            ->assertRedirectContains($scopeInUrl);
    }

    public static function scopesProvider(): array
    {
        return [
            'no scopes' => [[], 'scope=openid'],
            'one scope' => [['test-scope-1'], 'scope=test-scope-1+openid'],
            'multiple scopes' => [['test-scope-1', 'test-scope-2'], 'scope=test-scope-1+test-scope-2+openid'],
        ];
    }

    public function testLoginRouteRedirectsToAuthorizeUrlOfProviderWithLoginHint(): void
    {
        $this->mockOpenIDConfigurationLoader();

        config()->set('oidc.client_id', 'test-client-id');

        $response = $this->get(route('oidc.login', ['login_hint' => 'test-login-hint']));
        $response
            ->assertStatus(302)
            ->assertRedirectContains("https://provider.rdobeheer.nl/authorize")
            ->assertRedirectContains('test-client-id')
            ->assertRedirectContains('login_hint=test-login-hint');
    }

    public function testLoginRouteReturnsUserInfoWitchMockedClient(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('setLoginHint')
            ->once();
        $mockClient
            ->shouldReceive('authenticate')
            ->once();

        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andReturn((object) [
                'sub' => 'test-sub',
                'name' => 'test-name',
                'email' => 'test-email',
            ]);

        $this->app->instance(OpenIDConnectClient::class, $mockClient);

        $response = $this->get(route('oidc.login'));
        $response
            ->assertJson([
                'userInfo' => [
                    'sub' => 'test-sub',
                    'name' => 'test-name',
                    'email' => 'test-email',
                ],
            ]);
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
}
