<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel;

use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfiguration;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptInterface;

/**
 * OpenID Connect Client for Laravel
 */
class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    protected ?JweDecryptInterface $jweDecrypter;
    protected ?OpenIDConfiguration $openIDConfiguration;

    public function __construct(
        ?string $providerUrl = null,
        ?string $clientId = null,
        ?string $clientSecret = null,
        ?string $issuer = null,
        ?JweDecryptInterface $jweDecrypter = null,
        ?OpenIDConfiguration $openIDConfiguration = null,
    ) {
        parent::__construct($providerUrl, $clientId, $clientSecret, $issuer);

        $this->jweDecrypter = $jweDecrypter;
        $this->openIDConfiguration = $openIDConfiguration;
    }

    protected function startSession(): void
    {
        // Laravel magic in the background :)
    }

    protected function commitSession(): void
    {
        Session::save();
    }

    /**
     * @param string $key
     */
    protected function getSessionKey($key): mixed
    {
        if (!Session::has($key)) {
            return false;
        }

        return Session::get($key);
    }

    /**
     * @param string $key
     * @param mixed $value mixed
     */
    protected function setSessionKey($key, $value): void
    {
        Session::put($key, $value);
    }

    /**
     * @param string $key
     */
    protected function unsetSessionKey($key): void
    {
        Session::remove($key);
    }

    /**
     * @param string $jwe The JWE to decrypt
     * @return string the JWT payload
     * @throws OpenIDConnectClientException
     */
    protected function handleJweResponse($jwe): string
    {
        if ($this->jweDecrypter === null) {
            throw new OpenIDConnectClientException(
                'JWE response is not supported, please set the jwe decrypter.'
            );
        }
        return $this->jweDecrypter->decrypt($jwe);
    }

    /**
     * Use cached OpenID configuration if available.
     *
     * @param string $param
     * @param string|string[]|bool|null $default optional
     * @throws OpenIDConnectClientException
     * @return string|string[]|bool
     */
    protected function getWellKnownConfigValue($param, $default = null): string|array|bool
    {
        if ($this->openIDConfiguration === null) {
            return parent::getWellKnownConfigValue($param, $default);
        }

        $config = $this->openIDConfiguration;
        $param = Str::camel($param);

        if (!property_exists($config, $param)) {
            return parent::getWellKnownConfigValue($param, $default);
        }

        return $config->{$param};
    }

    /**
     * Set login hint when redirecting to authorization endpoint.
     * Is used when redirecting to the authorization endpoint.
     * @param string|null $loginHint
     * @return void
     */
    public function setLoginHint(?string $loginHint = null): void
    {
        $this->addAuthParam(['login_hint' => $loginHint]);
    }

    /**
     * Overwrite the redirect method to a redirect method of Laravel.
     * Sometimes the error 'Cannot modify header information - headers already sent' was thrown.
     * By using HttpResponseException, laravel will return the given response.
     * @param string $url
     * @return void
     * @throws OpenIDConnectClientException
     */
    public function redirect($url): void
    {
        throw new HttpResponseException(new RedirectResponse($url));
    }

    /**
     * Get authorization_endpoint from openid configuration.
     * @throws OpenIDConnectClientException
     */
    protected function getAuthorizationEndpoint(): string
    {
        if ($this->openIDConfiguration !== null) {
            return $this->openIDConfiguration->authorizationEndpoint;
        }

        $authorizationEndpoint = $this->getWellKnownConfigValue('authorization_endpoint');
        if (!is_string($authorizationEndpoint)) {
            throw new OpenIDConnectClientException(
                'No authorization endpoint found in well-known config.'
            );
        }

        return $authorizationEndpoint;
    }
}
