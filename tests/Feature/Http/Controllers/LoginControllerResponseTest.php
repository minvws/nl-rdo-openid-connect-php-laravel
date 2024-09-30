<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Feature\Http\Controllers;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Illuminate\Testing\TestResponse;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfiguration;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoader;
use MinVWS\OpenIDConnectLaravel\Services\ExceptionHandlerInterface;
use MinVWS\OpenIDConnectLaravel\Tests\TestCase;
use Mockery;

use function MinVWS\OpenIDConnectLaravel\Tests\{
    generateJwt,
    generateOpenSSLKey,
};

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

        Config::set('oidc.client_id', 'test-client-id');
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

        $response = $this->getRoute('oidc.login', ['error' => 'test-error']);

        $response
            ->assertStatus(400);
    }

    public function testNonceAndStateAreSetInCache(): void
    {
        $this->mockOpenIDConfigurationLoader();

        // Check if nonce and state are not set in cache.
        $this->assertNull(session('openid_connect_nonce'));
        $this->assertNull(session('openid_connect_state'));

        // Make request to login route.
        $response = $this->getRoute('oidc.login');

        // Now the nonce and state should be set and should be in the url
        $nonce = session('openid_connect_nonce');
        $state = session('openid_connect_state');

        $response
            ->assertStatus(302)
            ->assertRedirectContains("https://provider.rdobeheer.nl/authorize")
            ->assertRedirectContains('response_type=code')
            ->assertRedirectContains('redirect_uri=http%3A%2F%2Flocalhost%2Foidc%2Flogin')
            ->assertRedirectContains('client_id=test-client-id')
            ->assertRedirectContains('nonce=' . $nonce)
            ->assertRedirectContains('state=' . $state)
            ->assertRedirectContains('client_id=test-client-id');
    }

    /**
     * @dataProvider codeChallengeMethodProvider
     */
    public function testCodeChallengeIsSetWhenSupported(
        ?string $requestedCodeChallengeMethod,
        array $codeChallengesSupportedAtProvider,
        bool $codeChallengeShouldBeSet,
    ): void {
        $this->mockOpenIDConfigurationLoader(
            codeChallengeMethodsSupported: $codeChallengesSupportedAtProvider,
        );
        Config::set('oidc.code_challenge_method', $requestedCodeChallengeMethod);

        // Check if code verified is not set in cache.
        $this->assertNull(session('openid_connect_code_verifier'));

        // Make request to login route.
        $response = $this->getRoute('oidc.login');

        $response
            ->assertStatus(302)
            ->assertRedirectContains("https://provider.rdobeheer.nl/authorize");

        if ($codeChallengeShouldBeSet) {
            $response
                ->assertRedirectContains('code_challenge_method=' . $requestedCodeChallengeMethod)
                ->assertRedirectContains('code_challenge=')
                ->assertSessionHas('openid_connect_code_verifier');
        } else {
            $response
                ->assertSessionMissing('openid_connect_code_verifier');
        }
    }

    public function codeChallengeMethodProvider(): array
    {
        return [
            'no code challenge method requested' => [null, [], false],
            'code challenge method requested but not supported' => ['S256', [], false],
            'code challenge method requested and supported' => ['S256', ['S256'], true],
            'code challenge method requested and supported plain' => ['plain', ['plain'], true],
        ];
    }

    public function testStateDoesNotMatch(): void
    {
        Http::fake([
            // Token requested by OpenIDConnectClient::authenticate() function.
            // Currently needed because the package requests the token endpoint before checking the state.
            // TODO: Remove if https://github.com/jumbojett/OpenID-Connect-PHP/pull/447 is merged.
            'https://provider.rdobeheer.nl/token' => Http::response([
                'access_token' => 'access-token-from-token-endpoint',
                'id_token' => 'some-valid-token-not-needed-for-this-state-check',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ]),
        ]);

        // Set OIDC config
        $this->mockOpenIDConfigurationLoader();
        Config::set('oidc.issuer', 'https://provider.rdobeheer.nl');
        Config::set('oidc.client_id', 'test-client-id');
        Config::set('oidc.client_secret', 'the-secret-client-secret');

        // Mock LoginResponseHandlerInterface to check handleExceptionWhileAuthenticate is called.
        $mock = Mockery::mock(ExceptionHandlerInterface::class);
        $mock
            ->shouldReceive('handleExceptionWhileAuthenticate')
            ->withArgs(function (OpenIDConnectClientException $e) {
                return $e->getMessage() === 'Unable to determine state';
            })
            ->once();
        $this->app->instance(ExceptionHandlerInterface::class, $mock);

        // Set the current state, which is usually generated and saved in the session before login,
        // and sent to the issuer during the login redirect.
        Session::put('openid_connect_state', 'some-state');

        // We simulate here that the state does not match with the state in the session.
        $this->getRoute('oidc.login', ['code' => 'some-code', 'state' => 'a-different-state']);
    }

    public function testIdTokenSignedWithClientSecret(): void
    {
        $idToken = generateJwt([
            "iss" => "https://provider.rdobeheer.nl",
            "aud" => 'test-client-id',
            "sub" => 'test-subject',
        ], 'the-secret-client-secret');

        Http::fake([
            // Token requested by OpenIDConnectClient::authenticate() function.
            'https://provider.rdobeheer.nl/token' => Http::response([
                'access_token' => 'access-token-from-token-endpoint',
                'id_token' => $idToken,
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ]),
            // User info requested by OpenIDConnectClient::requestUserInfo() function.
            'https://provider.rdobeheer.nl/userinfo?schema=openid' => Http::response([
                'email' => 'tester@rdobeheer.nl',
            ]),
        ]);

        // Set OIDC config
        $this->mockOpenIDConfigurationLoader();

        Config::set('oidc.issuer', 'https://provider.rdobeheer.nl');
        Config::set('oidc.client_id', 'test-client-id');
        Config::set('oidc.client_secret', 'the-secret-client-secret');

        // Set the current state, which is usually generated and saved in the session before login,
        // and sent to the issuer during the login redirect.
        Session::put('openid_connect_state', 'some-state');

        // We simulate here that the user now comes back after successful login at issuer.
        $response = $this->getRoute('oidc.login', ['code' => 'some-code', 'state' => 'some-state']);
        $response->assertStatus(200);
        $response->assertJson([
            'userInfo' => [
                'email' => 'tester@rdobeheer.nl',
            ]
        ]);

        $this->assertEmpty(session('openid_connect_state'));
        $this->assertEmpty(session('openid_connect_nonce'));

        Http::assertSentCount(2);
        Http::assertSentInOrder([
            'https://provider.rdobeheer.nl/token',
            'https://provider.rdobeheer.nl/userinfo?schema=openid',
        ]);
        Http::assertSent(function (Request $request) {
            if ($request->url() === 'https://provider.rdobeheer.nl/token') {
                $this->assertSame(
                    expected: 'POST',
                    actual: $request->method(),
                );
                $this->assertSame(
                    expected: 'grant_type=authorization_code'
                    . '&code=some-code'
                    . '&redirect_uri=http%3A%2F%2Flocalhost%2Foidc%2Flogin'
                    . '&client_id=test-client-id'
                    . '&client_secret=the-secret-client-secret',
                    actual: $request->body(),
                );
                return true;
            }

            if ($request->url() === 'https://provider.rdobeheer.nl/userinfo?schema=openid') {
                $this->assertSame(
                    expected: 'GET',
                    actual: $request->method(),
                );
                $this->assertSame(
                    expected: [
                        'Bearer access-token-from-token-endpoint'
                    ],
                    actual: $request->header('Authorization'),
                );
            }

            return true;
        });
    }

    public function testTokenSignedWithPrivateKey(): void
    {
        Http::fake([
            // Token requested by OpenIDConnectClient::authenticate() function.
            'https://provider.rdobeheer.nl/token' => Http::response([
                'access_token' => 'access-token-from-token-endpoint',
                'id_token' => 'does-not-matter-not-testing-id-token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ]),
        ]);

        // Set OIDC provider configuration
        $this->mockOpenIDConfigurationLoader(tokenEndpointAuthMethodsSupported: ['private_key_jwt']);

        Config::set('oidc.issuer', 'https://provider.rdobeheer.nl');
        Config::set('oidc.client_id', 'test-client-id');

        // Set client private key
        [$key, $keyResource] = generateOpenSSLKey();
        Config::set('oidc.client_authentication.signing_private_key_path', stream_get_meta_data($keyResource)['uri']);

        // Set the current state, which is usually generated and saved in the session before login,
        // and sent to the issuer during the login redirect.
        Session::put('openid_connect_state', 'some-state');

        // We simulate here that the user now comes back after successful login at issuer.
        $this->getRoute('oidc.login', ['code' => 'some-code', 'state' => 'some-state']);

        // Check if state and nonce are removed from session.
        $this->assertEmpty(session('openid_connect_state'));
        $this->assertEmpty(session('openid_connect_nonce'));

        Http::assertSentCount(1);
        Http::assertSentInOrder([
            'https://provider.rdobeheer.nl/token',
        ]);
        Http::assertSent(function (Request $request) {
            if (!in_array($request->url(), ['https://provider.rdobeheer.nl/token'], true)) {
                return false;
            }

            if ($request->url() === 'https://provider.rdobeheer.nl/token') {
                $this->assertSame(
                    expected: 'POST',
                    actual: $request->method(),
                );

                // We only check if the client_assertion is set in the request body.
                // The JWT of the PrivateKeyJWTBuilder is tested in a separate test.
                $this->assertStringStartsWith(
                    prefix: 'grant_type=authorization_code'
                    . '&code=some-code'
                    . '&redirect_uri=http%3A%2F%2Flocalhost%2Foidc%2Flogin'
                    . '&client_id=test-client-id'
                    . '&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer'
                    . '&client_assertion=eyJhbGciOiJSUzI1NiJ9.',
                    string: $request->body(),
                );

                return true;
            }

            return true;
        });
    }

    protected function mockOpenIDConfigurationLoader(
        array $tokenEndpointAuthMethodsSupported = ["none"],
        array $codeChallengeMethodsSupported = [],
    ): void {
        $mock = Mockery::mock(OpenIDConfigurationLoader::class);
        $mock
            ->shouldReceive('getConfiguration')
            ->andReturn($this->exampleOpenIDConfiguration(
                tokenEndpointAuthMethodsSupported: $tokenEndpointAuthMethodsSupported,
                codeChallengeMethodsSupported: $codeChallengeMethodsSupported,
            ));

        $this->app->instance(OpenIDConfigurationLoader::class, $mock);
    }

    protected function exampleOpenIDConfiguration(
        array $tokenEndpointAuthMethodsSupported = ["none"],
        array $codeChallengeMethodsSupported = [],
    ): OpenIDConfiguration {
        return new OpenIDConfiguration(
            version: "3.0",
            tokenEndpointAuthMethodsSupported: $tokenEndpointAuthMethodsSupported,
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
            codeChallengeMethodsSupported: $codeChallengeMethodsSupported,
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
