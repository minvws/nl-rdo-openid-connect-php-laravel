<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel;

use Illuminate\Support\Facades\Session;
use Jumbojett\OpenIDConnectClient as BaseOpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptInterface;

class OpenIDConnectClient extends BaseOpenIDConnectClient
{
    protected ?JweDecryptInterface $jweDecrypter;

    public function __construct(
        ?string $providerUrl = null,
        ?string $clientId = null,
        ?string $clientSecret = null,
        ?string $issuer = null,
        ?JweDecryptInterface $jweDecrypter = null
    ) {
        /**
         * @phpstan-ignore-next-line Because parent constructor type block is wrong
         * @psalm-suppress InvalidArgument
         */
        parent::__construct($providerUrl, $clientId, $clientSecret, $issuer);

        $this->jweDecrypter = $jweDecrypter;
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
}
