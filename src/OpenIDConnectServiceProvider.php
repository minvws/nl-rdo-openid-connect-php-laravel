<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponse;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseInterface;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfigurationLoader;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptInterface;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptService;
use MinVWS\OpenIDConnectLaravel\Services\OpenIDConnectExceptionHandler;
use MinVWS\OpenIDConnectLaravel\Services\OpenIDConnectExceptionHandlerInterface;

class OpenIDConnectServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/oidc.php', 'oidc');

        $this->registerJweDecryptInterface();
        $this->registerConfigurationLoader();
        $this->registerClient();
        $this->registerExceptionHandler();
        $this->registerResponses();
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

    protected function registerConfigurationLoader(): void
    {
        $this->app->singleton(OpenIDConfigurationLoader::class, function (Application $app) {
            return new OpenIDConfigurationLoader(
                $app['config']->get('oidc.issuer'),
                $app['config']->get('oidc.cache_ttl'),
                $app['config']->get('oidc.cache_store'),
            );
        });
    }

    protected function registerClient(): void
    {
        $this->app->singleton(OpenIDConnectClient::class, function (Application $app) {
            $oidc = new OpenIDConnectClient(
                providerUrl: $app['config']->get('oidc.issuer'),
                jweDecrypter: $app->make(JweDecryptInterface::class)
            );
            $oidc->setClientID($app['config']->get('oidc.client_id'));
            if (!empty($app['config']->get('oidc.client_secret'))) {
                $oidc->setClientSecret($app['config']->get('oidc.client_secret'));
            }
            $oidc->setCodeChallengeMethod($app['config']->get('oidc.code_challenge_method'));
            $oidc->setRedirectURL($app['url']->route('oidc.login'));

            foreach ($app['config']->get('oidc.additional_scopes') as $scope) {
                $oidc->addScope($scope);
            }
            return $oidc;
        });
    }

    protected function registerJweDecryptInterface(): void
    {
        $this->app->singleton(JweDecryptInterface::class, function (Application $app) {
            return new JweDecryptService(decryptionKeyPath: $app['config']->get('oidc.decryption_key_path'));
        });
    }

    protected function registerExceptionHandler(): void
    {
        $this->app->bind(OpenIDConnectExceptionHandlerInterface::class, OpenIDConnectExceptionHandler::class);
    }
    protected function registerResponses(): void
    {
        $this->app->bind(LoginResponseInterface::class, LoginResponse::class);
    }
}
