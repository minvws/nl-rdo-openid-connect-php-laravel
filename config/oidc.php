<?php

declare(strict_types=1);

return [
    /**
     * The issuer URL of the OpenID Connect provider.
     */
    'issuer' => env('OIDC_ISSUER', ''),

    /**
     * The unique identifier assigned to your application
     * by the OpenID Connect provider.
     */
    'client_id' => env('OIDC_CLIENT_ID', ''),

    /**
     * If needed, the client secret that you received
     * from the OpenID Connect provider.
     */
    'client_secret' => env('OIDC_CLIENT_SECRET', ''),

    /**
     * Configuration for client authentication.
     *
     * By default, the client authentication method used is either `client_secret_basic`, `client_secret_post`,
     * `client_secret_jwt`, or no authentication, depending on provider support.
     * To use `private_key_jwt` client authentication, configure the options below.
     */
    'client_authentication' => [

        /**
         * The file path to the private key used for client authentication.
         * This private key is required for signing the JWT when using `private_key_jwt` client authentication.
         *
         * Example: '/path/to/private.key'
         */
        'signing_private_key_path' => env('OIDC_SIGNING_PRIVATE_KEY_PATH'),

        /**
         * The signing algorithm used for `private_key_jwt` client authentication.
         *
         * Default: 'RS256'
         * Example Values: 'RS256', 'HS256', 'ES256'
         * For a list of supported algorithms, see https://tools.ietf.org/html/rfc7518#section-3.1
         */
        'signing_algorithm' => env('OIDC_SIGNING_ALGORITHM', 'RS256'),

        /**
         * A list of signature algorithms available for use.
         * This list is used to configure the AlgorithmManager and should include class names.
         *
         * For more details, see https://web-token.spomky-labs.com/the-components/algorithm-management-jwa
         */
        'signature_algorithms' => [
            \Jose\Component\Signature\Algorithm\RS256::class,
        ],

        /**
         * The duration (in seconds) for which the token remains valid.
         * This sets the expiration time of the JWT when using `private_key_jwt` client authentication.
         */
        'token_lifetime_in_seconds' => 60,

    ],

    /**
     * Path to the private key used to decrypt the JWE response from the user info endpoint.
     * This is only required when the response from the user info endpoint is encrypted.
     *
     * Multiple decryption key paths can be specified, separated by commas.
     */
    'decryption_key_path' => env('OIDC_DECRYPTION_KEY_PATH', ''),

    /**
     * By default, the openid scope is requested. If you need additional scopes, you can specify them here.
     */
    'additional_scopes' => array_filter(explode(',', env('OIDC_ADDITIONAL_SCOPES', ''))),

    /**
     * Code Challenge Method used for PKCE.
     */
    'code_challenge_method' => env('OIDC_CODE_CHALLENGE_METHOD', 'S256'),

    /**
     * Configuration Cache
     */
    'configuration_cache' => [

        /**
         * The cache store to use.
         */
        'store' => env('OIDC_CONFIGURATION_CACHE_DRIVER', 'file'),

        /**
         * The cache TTL in seconds.
         */
        'ttl' => env('OIDC_CONFIGURATION_CACHE_TTL', 60 * 60 * 24),

    ],

    /**
     * Route configuration
     */
    'route_configuration' => [

        /**
         * Enable or disable the login route.
         */
        'enabled' => env('OIDC_LOGIN_ROUTE_ENABLED', true),

        /**
         * The url of the login route.
         */
        'login_route' => env('OIDC_LOGIN_ROUTE', '/oidc/login'),

        /**
         * The middleware that runs on the login route.
         */
        'middleware' => [
            'web'
        ],

        /**
         * The prefix of the login route.
         */
        'prefix' => '',

    ],

    /**
     * TLS Verify - Used as the verify option for Guzzle.
     *
     * Default is true and verifies the certificate and uses the default CA bundle of the system.
     * When set to `false` it disables the certificate verification (this is insecure!).
     * When set to a path of a CA bundle, the custom certificate is used.
     *
     * @link https://docs.guzzlephp.org/en/latest/request-options.html#verify
     */
    'tls_verify' => env('OIDC_TLS_VERIFY', true),
];
