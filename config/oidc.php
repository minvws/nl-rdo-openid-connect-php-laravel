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
     * TTL of the OpenID configuration cache in seconds.
     */
    'configuration_cache_ttl' => env('OIDC_CONFIGURATION_CACHE_TTL', 60 * 60 * 24),

    /**
     * Route configuration
     */
    'route_configuration' => [
        'login_route' => env('OIDC_LOGIN_ROUTE', '/oidc/login'),
        'middleware' => [
            'web'
        ],
        'prefix' => '',
    ]
];
