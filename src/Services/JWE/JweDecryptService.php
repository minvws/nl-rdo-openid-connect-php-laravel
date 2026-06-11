<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services\JWE;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\JWEDecrypter;

class JweDecryptService implements JweDecryptInterface
{
    public function __construct(
        protected JWKSet $decryptionKeySet,
        protected JweSerializerManagerInterface $serializerManager = new NativeJweSerializerManager(),
        protected JWEDecrypter $jweDecrypter = new JWEDecrypter(
            new AlgorithmManager([new RSAOAEP(), new A128CBCHS256()])
        ),
    ) {
    }

    /**
     * @throws JweDecryptException
     */
    #[\Override]
    public function decrypt(string $jweString): string
    {
        $jwe = $this->serializerManager->unserialize($jweString);

        // Success of decryption, $jwe is now decrypted
        $success = $this->jweDecrypter->decryptUsingKeySet($jwe, $this->decryptionKeySet, 0);
        if (!$success) {
            throw new JweDecryptException('Failed to decrypt JWE');
        }

        $payload = $jwe->getPayload();
        if ($payload === null) {
            throw new JweDecryptException('Payload of JWE is null');
        }

        return $payload;
    }
}
