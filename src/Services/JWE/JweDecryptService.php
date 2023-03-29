<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services\JWE;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;

class JweDecryptService implements JweDecryptInterface
{
    public function __construct(
        protected string $decryptionKeyPath,
    ) {
    }

    /**
     * @throws JweDecryptException
     */
    public function decrypt(string $jweString): string
    {
        $jweDecrypter = $this->getDecrypter();

        $serializerManager = new JWESerializerManager([new CompactSerializer()]);
        $jwe = $serializerManager->unserialize($jweString);

        // Success of decryption, $jwe is now decrypted
        $success = $jweDecrypter->decryptUsingKey($jwe, $this->getDecryptionKey(), 0);
        if (!$success) {
            throw new JweDecryptException('Failed to decrypt JWE');
        }

        $payload = $jwe->getPayload();
        if ($payload === null) {
            throw new JweDecryptException('Payload of JWE is null');
        }

        return $payload;
    }

    protected function getDecrypter(): JWEDecrypter
    {
        $keyEncryptionAlgorithmManager = new AlgorithmManager([new RSAOAEP()]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([new A128CBCHS256()]);
        $compressionMethodManager = new CompressionMethodManager([new Deflate()]);

        return new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );
    }

    protected function getDecryptionKey(): JWK
    {
        return JWKFactory::createFromKeyFile($this->decryptionKeyPath);
    }
}
