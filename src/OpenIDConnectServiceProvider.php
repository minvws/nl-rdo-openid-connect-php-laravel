<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseHandler;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseHandlerInterface;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoader;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptInterface;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptService;
use MinVWS\OpenIDConnectLaravel\Services\ExceptionHandler;
use MinVWS\OpenIDConnectLaravel\Services\ExceptionHandlerInterface;
use MinVWS\OpenIDConnectLaravel\Services\JWS\PrivateKeyJWTBuilder;

class OpenIDConnectServiceProvider extends ServiceProvider
{
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/oidc.php', 'oidc');

        $this->registerJweDecryptInterface();
        $this->registerConfigurationLoader();
        $this->registerClient();
        $this->registerExceptionHandler();
        $this->registerResponseHandler();
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/oidc.php' => config_path('oidc.php'),
            ], 'config');
        }

        $this->registerRoutes();
    }

    protected function registerRoutes(): void
    {
        if (!$this->routesEnabled()) {
            return;
        }

        Route::group($this->routeConfiguration(), function () {
            $this->loadRoutesFrom(__DIR__ . '/../routes/oidc.php');
        });
    }

    /**
     * Get the OpenID Connect route group configuration array.
     *
     * @return array<string, mixed>
     */
    protected function routeConfiguration(): array
    {
        return [
            'prefix' => config('oidc.route_configuration.prefix'),
            'middleware' => config('oidc.route_configuration.middleware'),
        ];
    }

    /**
     * Check in config if the routes are enabled.
     *
     * @return bool
     */
    protected function routesEnabled(): bool
    {
        $enabled = config('oidc.route_configuration.enabled');
        if (!is_bool($enabled)) {
            return false;
        }

        return $enabled;
    }

    protected function registerConfigurationLoader(): void
    {
        $this->app->singleton(OpenIDConfigurationLoader::class, function (Application $app) {
            return new OpenIDConfigurationLoader(
                $app['config']->get('oidc.issuer'),
                $app['cache']->store($app['config']->get('oidc.configuration_cache.store')),
                $app['config']->get('oidc.configuration_cache.ttl'),
                $app['config']->get('oidc.tls_verify'),
            );
        });
    }

    protected function registerClient(): void
    {
        $this->app->singleton(OpenIDConnectClient::class, function (Application $app) {
            $clientId = $app['config']->get('oidc.client_id');

            $oidc = new OpenIDConnectClient(
                providerUrl: $app['config']->get('oidc.issuer'),
                jweDecrypter: $app->make(JweDecryptInterface::class),
                openIDConfiguration: $app->make(OpenIDConfigurationLoader::class)->getConfiguration(),
            );
            $oidc->setClientID($clientId);
            if (!empty($app['config']->get('oidc.client_secret'))) {
                $oidc->setClientSecret($app['config']->get('oidc.client_secret'));
            }
            if (!empty($app['config']->get('oidc.code_challenge_method'))) {
                $oidc->setCodeChallengeMethod($app['config']->get('oidc.code_challenge_method'));
            }
            $oidc->setRedirectURL($app['url']->route('oidc.login'));

            $additionalScopes = $app['config']->get('oidc.additional_scopes');
            if (is_array($additionalScopes) && count($additionalScopes) > 0) {
                $oidc->addScope($additionalScopes);
            }

            $oidc->setTlsVerify($app['config']->get('oidc.tls_verify'));

            $signingPrivateKeyPath = $app['config']->get('oidc.client_authentication.signing_private_key_path');
            if (!empty($signingPrivateKeyPath)) {
                $algorithms = $this->parseSignatureAlgorithms($app['config']);
                $signingPrivateKey = JWKFactory::createFromKeyFile($signingPrivateKeyPath);
                $singingAlgorithm = $app['config']->get('oidc.client_authentication.signing_algorithm');
                $tokenLifetimeInSeconds = $app['config']->get('oidc.client_authentication.token_lifetime_in_seconds');

                $privateKeyJwtBuilder = new PrivateKeyJWTBuilder(
                    clientId: $clientId,
                    jwsBuilder: new JWSBuilder(new AlgorithmManager($algorithms)),
                    signatureKey: $signingPrivateKey,
                    signatureAlgorithm: $singingAlgorithm,
                    serializer: new CompactSerializer(),
                    tokenLifetimeInSeconds: $tokenLifetimeInSeconds,
                );

                // Set private key JWT generator and explicit allow of private_key_jwt
                $oidc->setPrivateKeyJwtGenerator($privateKeyJwtBuilder);
                $oidc->setTokenEndpointAuthMethodsSupported(['private_key_jwt']);
            }

            return $oidc;
        });
    }

    protected function registerJweDecryptInterface(): void
    {
        $this->app->singleton(JweDecryptInterface::class, function () {
            $decryptionKeySet = $this->parseDecryptionKeySet();
            if ($decryptionKeySet === null) {
                return null;
            }

            return new JweDecryptService(decryptionKeySet: $decryptionKeySet);
        });
    }

    protected function registerExceptionHandler(): void
    {
        $this->app->bind(ExceptionHandlerInterface::class, ExceptionHandler::class);
    }
    protected function registerResponseHandler(): void
    {
        $this->app->bind(LoginResponseHandlerInterface::class, LoginResponseHandler::class);
    }

    /**
     * Parse decryption keys from config
     * @return ?JWKSet
     */
    protected function parseDecryptionKeySet(): ?JWKSet
    {
        $value = config('oidc.decryption_key_path');
        if (empty($value)) {
            return null;
        }

        $keys = [];

        $paths = explode(',', $value);
        foreach ($paths as $path) {
            $keys[] = JWKFactory::createFromKeyFile($path);
        }

        return new JWKSet($keys);
    }

    /**
     * @param ConfigRepository $config
     * @return array<Algorithm>
     */
    protected function parseSignatureAlgorithms(ConfigRepository $config): array
    {
        /** @var ?array<class-string<Algorithm>> $algorithms */
        $algorithms = $config->get('oidc.client_authentication.signature_algorithms');
        if (!is_array($algorithms)) {
            return [];
        }

        return array_map(function (string $algorithm) {
            return new $algorithm();
        }, $algorithms);
    }
}
