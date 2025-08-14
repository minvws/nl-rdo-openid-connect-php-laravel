<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\OpenIDConfiguration;

/**
 * Class OpenIDConfiguration
 * Based on the OpenID Provider Metadata specification.
 * @link https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 */
class OpenIDConfiguration
{
    /**
     * @param string $version
     * @param string[] $tokenEndpointAuthMethodsSupported
     * @param bool $claimsParameterSupported
     * @param bool $requestParameterSupported
     * @param bool $requestUriParameterSupported
     * @param bool $requireRequestUriRegistration
     * @param string[] $grantTypesSupported
     * @param bool $frontchannelLogoutSupported
     * @param bool $frontchannelLogoutSessionSupported
     * @param bool $backchannelLogoutSupported
     * @param bool $backchannelLogoutSessionSupported
     * @param string $issuer
     * @param string $authorizationEndpoint
     * @param string $jwksUri
     * @param string $tokenEndpoint
     * @param string[] $scopesSupported
     * @param string[] $responseTypesSupported
     * @param string[] $responseModesSupported
     * @param string[] $subjectTypesSupported
     * @param string[] $idTokenSigningAlgValuesSupported
     * @param string $userinfoEndpoint
     * @param string[] $codeChallengeMethodsSupported
     */
    public function __construct(
        public string $version = '',
        public array $tokenEndpointAuthMethodsSupported = [],
        public bool $claimsParameterSupported = false,
        public bool $requestParameterSupported = false,
        public bool $requestUriParameterSupported = false,
        public bool $requireRequestUriRegistration = false,
        public array $grantTypesSupported = [],
        public bool $frontchannelLogoutSupported = false,
        public bool $frontchannelLogoutSessionSupported = false,
        public bool $backchannelLogoutSupported = false,
        public bool $backchannelLogoutSessionSupported = false,
        public string $issuer = '',
        public string $authorizationEndpoint = '',
        public string $jwksUri = '',
        public string $tokenEndpoint = '',
        public array $scopesSupported = [],
        public array $responseTypesSupported = [],
        public array $responseModesSupported = [],
        public array $subjectTypesSupported = [],
        public array $idTokenSigningAlgValuesSupported = [],
        public string $userinfoEndpoint = '',
        public array $codeChallengeMethodsSupported = [],
        public string $endSessionEndpoint = '',
    ) {
    }
}
