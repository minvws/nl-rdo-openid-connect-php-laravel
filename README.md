# OpenID Connect Package for Laravel
This package is an OpenID Connect implementation for Laravel, based on the [jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP) package. It provides a convenient way to integrate OpenID Connect into your Laravel application.

## Requirements
Before using the OpenID Connect package for Laravel, ensure that your development environment meets the following requirements:

- PHP 8.1 or higher: The package requires at least PHP version 8.1. Make sure you have PHP installed and configured properly on your system.
- Laravel: The package is designed to work with Laravel, so you should have a Laravel application set up and running.
- Composer: Composer is a dependency manager for PHP. You will need Composer installed to install and manage the package and its dependencies.

If your environment meets these requirements, you can proceed with the installation and configuration of the OpenID Connect package.

## Installation

You can install the package via Composer package manager:

```bash
composer require minvws/openid-connect-php-laravel
```

For Laravel, publish the configuration file:

```bash
php artisan vendor:publish --provider="MinVWS\OpenIDConnect\OpenIDConnectServiceProvider"
```

This command will publish the configuration file to your Laravel application's config directory. The configuration file is named `oidc.php`.


## Configuration
To use this package, you need to configure the following variables in your Laravel application's .env file or through environment variables:

- `OIDC_ISSUER`: The issuer URL of the OpenID Connect provider.
- `OIDC_CLIENT_ID`: The client ID of the OpenID Connect provider.
- `OIDC_CLIENT_SECRET`: If needed, the client secret of the OpenID Connect provider.
- `OIDC_DECRYPTION_KEY_PATH`: Only needed when the response of the user info endpoint is encrypted. This is the path to the JWE decryption key.
- `OIDC_ADDITIONAL_SCOPES`: By default, the openid scope is requested. If you need additional scopes, you can specify them here as a comma-separated list.
- `OIDC_CODE_CHALLENGE_METHOD`: Code Challenge Method used for Proof Key for Code Exchange (PKCE). The default value is S256.

### Cache Configuration 
The package provides a configurable cache for caching the OpenID Connect configuration. You can customize the behavior of the cache using the following configuration options:

- `OIDC_CONFIGURATION_CACHE_DRIVER`: The cache store to use for caching OpenID Connect configuration.
- `OIDC_CONFIGURATION_CACHE_TTL`: The cache TTL (time-to-live) in seconds for the OpenID Connect configuration.

### Route Configuration
The package provides a configurable login route for OpenID Connect authentication. You can customize the behavior of the login route using the following configuration options:

- `OIDC_LOGIN_ROUTE_ENABLED`: Enable or disable the login route. Set this value to true or false.
- `OIDC_LOGIN_ROUTE`: The URL of the login route.
- `OIDC_LOGIN_ROUTE_MIDDLEWARE`: The middleware that runs on the login route. By default, the web middleware is applied.
- `OIDC_LOGIN_ROUTE_PREFIX`: The prefix of the login route.

## Usage
Once you have configured the necessary variables, you can go to the `/oidc/login` route that is available by default.

### Login Route
The package provides a pre-configured login route for OpenID Connect authentication. The login route is available out of the box and can be accessed at `/oidc/login`.

To enable or disable the login route, you can update the `OIDC_LOGIN_ROUTE_ENABLED` variable in your environment configuration. Set it to true to enable the login route or false to disable it.
To change the URL of the login route, you can update the `OIDC_LOGIN_ROUTE` variable in your environment configuration. The default value is `/oidc/login`.

### Customizing Login Response
The package includes a default LoginResponse class that returns a JSON response containing user information. However, you have the flexibility to customize the login response according to your project's needs.

To bind your own implementation of the LoginResponseInterface, you can use the following code in your Laravel application:
```php
$this->app->bind(LoginResponseInterface::class, YourCustomLoginResponse::class);
```

Replace `YourCustomLoginResponse` with the class name of your custom implementation. By binding your own response class, you can define the desired behavior and format of the login response.

Make sure to implement the `LoginResponseInterface` in your custom response class to ensure compatibility.

## Contributing
If you encounter any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request on the GitHub repository of this package.

## License
This package is open-source and released under the [European Union Public License version 1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12). You are free to use, modify, and distribute the package in accordance with the terms of the license.