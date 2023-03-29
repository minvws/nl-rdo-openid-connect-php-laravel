<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\OpenIDConfiguration;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Http;

class OpenIDConfigurationLoader
{
    public function __construct(
        protected string $issuer,
        protected ?Repository $cacheStore = null,
        protected int $cacheTtl = 3600,
    ) {
    }

    /**
     * @throws OpenIDConfigurationLoaderException
     */
    public function getConfiguration(): OpenIDConfiguration
    {
        if (!$this->cacheStore) {
            return $this->getConfigurationFromIssuer();
        }

        return $this->cacheStore->remember('openid-configuration', $this->cacheTtl, function () {
            return $this->getConfigurationFromIssuer();
        });
    }

    /**
     * @throws OpenIDConfigurationLoaderException
     */
    protected function getConfigurationFromIssuer(): OpenIDConfiguration
    {
        $url = $this->getOpenIDConfigurationUrl();

        $response = Http::get($url);
        if (!$response->successful()) {
            throw new OpenIDConfigurationLoaderException(
                message: 'Could not load OpenID configuration from issuer',
                context: [
                    'issuer' => $this->issuer,
                    'url' => $url,
                    'response_status_code' => $response->status(),
                    'response' => $response,
                ],
            );
        }

        if (!is_array($response->json())) {
            throw new OpenIDConfigurationLoaderException(
                message: 'Response body of OpenID configuration is not JSON',
                context: [
                    'issuer' => $this->issuer,
                    'url' => $url,
                    'response_status_code' => $response->status(),
                    'response' => $response,
                    'response_body' => $response->body(),
                ],
            );
        }

        return new OpenIDConfiguration(
            version: $response->json('version', ''),
            tokenEndpointAuthMethodsSupported: $response->json('token_endpoint_auth_methods_supported', []),
            claimsParameterSupported: $response->json('claims_parameter_supported', false),
            requestParameterSupported: $response->json('request_parameter_supported', false),
            requestUriParameterSupported: $response->json('request_uri_parameter_supported', false),
            requireRequestUriRegistration: $response->json('require_request_uri_registration', false),
            grantTypesSupported: $response->json('grant_types_supported', []),
            frontchannelLogoutSupported: $response->json('frontchannel_logout_supported', false),
            frontchannelLogoutSessionSupported: $response->json('frontchannel_logout_session_supported', false),
            backchannelLogoutSupported: $response->json('backchannel_logout_supported', false),
            backchannelLogoutSessionSupported: $response->json('backchannel_logout_session_supported', false),
            issuer: $response->json('issuer', ''),
            authorizationEndpoint: $response->json('authorization_endpoint', ''),
            jwksUri: $response->json('jwks_uri', ''),
            tokenEndpoint: $response->json('token_endpoint', ''),
            scopesSupported: $response->json('scopes_supported', []),
            responseTypesSupported: $response->json('response_types_supported', []),
            responseModesSupported: $response->json('response_modes_supported', []),
            subjectTypesSupported: $response->json('subject_types_supported', []),
            idTokenSigningAlgValuesSupported: $response->json('id_token_signing_alg_values_supported', []),
            userinfoEndpoint: $response->json('userinfo_endpoint', ''),
            codeChallengeMethodsSupported: $response->json('code_challenge_methods_supported', [])
        );
    }

    protected function getOpenIDConfigurationUrl(): string
    {
        return $this->issuer . '/.well-known/openid-configuration';
    }
}
