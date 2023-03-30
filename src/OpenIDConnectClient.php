<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel;

use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Jumbojett\OpenIDConnectClient as BaseOpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\OpenIDConfiguration\OpenIDConfiguration;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptInterface;

class OpenIDConnectClient extends BaseOpenIDConnectClient
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
     * @param string $default optional
     * @throws OpenIDConnectClientException
     * @return string|string[]|bool
     * @psalm-suppress ImplementedReturnTypeMismatch
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
     * Overwrite the redirect method to use Laravel's abort method.
     * Sometimes the error 'Cannot modify header information - headers already sent' was thrown.
     * By using Laravel's abort method, this error is prevented.
     * @param string $url
     * @return void
     */
    public function redirect($url): void
    {
        App::abort(302, '', ['Location' => $url]);
    }
}
