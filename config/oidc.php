<?php

declare(strict_types=1);

return [
    /**
     * The issuer URL of the OpenID Connect provider.
     */
    'issuer' => env('OIDC_ISSUER', ''),

    /**
     * The client ID of the OpenID Connect provider.
     */
    'client_id' => env('OIDC_CLIENT_ID', ''),

    /**
     * If needed, the client secret of the OpenID Connect provider.
     */
    'client_secret' => env('OIDC_CLIENT_SECRET', ''),

    /**
     * Only needed when response of user info endpoint is encrypted.
     * This is the path to the JWE decryption key.
     */
    'decryption_key_path' => env('OIDC_DECRYPTION_KEY_PATH', ''),

    /**
     * By default, the openid scope is requested. If you need additional scopes, you can specify them here.
     */
    'additional_scopes' => explode(',', env('OIDC_ADDITIONAL_SCOPES', '')),

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
     * TLS Verify
     * Can be disabled for local development.
     * Is used in OpenIDConfigurationLoader and in the ServiceProvider for OpenIDConnectClient.
     */
    'tls_verify' => env('OIDC_TLS_VERIFY', true),
];
