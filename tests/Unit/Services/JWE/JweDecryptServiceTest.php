<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Unit\Services\JWE;

use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;
use JsonException;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptException;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptService;
use Mockery;
use OpenSSLCertificate;
use PHPUnit\Framework\TestCase;

use function MinVWS\OpenIDConnectLaravel\Tests\{
    generateOpenSSLKey,
    generateX509Certificate,
    getJwkFromResource,
    buildJweString,
    buildExamplePayload
};

class JweDecryptServiceTest extends TestCase
{
    /**
     * @var resource
     */
    protected $decryptionKeyResource;
    protected JWKSet $decryptionKeySet;
    protected OpenSSLCertificate $x509Certificate;

    protected function setUp(): void
    {
        parent::setUp();

        [$key, $keyResource] = generateOpenSSLKey();
        $this->decryptionKeyResource = $keyResource;

        $this->decryptionKeySet = new JWKSet([
            getJwkFromResource($keyResource),
        ]);

        $this->x509Certificate = generateX509Certificate($key);
    }

    protected function tearDown(): void
    {
        if (is_resource($this->decryptionKeyResource)) {
            fclose($this->decryptionKeyResource);
        }

        parent::tearDown();
    }

    public function testServiceCanBeCreated(): void
    {
        $jweDecryptService = new JweDecryptService($this->decryptionKeySet);

        $this->assertInstanceOf(JweDecryptService::class, $jweDecryptService);
    }

    /**
     * @throws JweDecryptException
     * @throws JsonException
     */
    public function testJweDecryption(): void
    {
        $payload = buildExamplePayload();

        $jwe = buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($this->x509Certificate)
        );

        $jweDecryptService = new JweDecryptService($this->decryptionKeySet);
        $decryptedPayload = $jweDecryptService->decrypt($jwe);

        $this->assertEquals($payload, $decryptedPayload);
    }

    /**
     * @throws JweDecryptException
     * @throws JsonException
     */
    public function testJweDecryptionThrowsExceptionWhenKeyIsNotCorrect(): void
    {
        $this->expectException(JweDecryptException::class);
        $this->expectExceptionMessage('Failed to decrypt JWE');

        // Create different key
        [$key, $keyResource] = generateOpenSSLKey();
        $jwk = getJwkFromResource($keyResource);
        $decryptionKeySet = new JWKSet([$jwk]);

        // Build JWE for default certificate
        $payload = buildExamplePayload();
        $jwe = buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($this->x509Certificate)
        );

        // Try to decrypt with different key
        $jweDecryptService = new JweDecryptService($decryptionKeySet);
        $jweDecryptService->decrypt($jwe);
    }

    /**
     * @throws JweDecryptException
     * @throws JsonException
     */
    public function testJweDecryptionThrowsExceptionWhenPayloadIsNull(): void
    {
        $this->expectException(JweDecryptException::class);
        $this->expectExceptionMessage('Payload of JWE is null');

        $jweMock = Mockery::mock(JWE::class);
        $jweMock
            ->shouldReceive('getPayload')
            ->andReturn(null);

        $decryptionKeySet = Mockery::mock(JWKSet::class);
        $serializerManager = Mockery::mock(JWESerializerManager::class);
        $serializerManager
            ->shouldReceive('unserialize')
            ->with('something')
            ->andReturn($jweMock);

        $jweDecrypter = Mockery::mock(JWEDecrypter::class);
        $jweDecrypter
            ->shouldReceive('decryptUsingKeySet')
            ->andReturn(true);

        $decryptService = new JweDecryptService(
            $decryptionKeySet,
            $serializerManager,
            $jweDecrypter,
        );

        $decryptService->decrypt('something');
    }

    /**
     * @throws JweDecryptException
     * @throws JsonException
     */
    public function testJweDecryptionWithMultipleKeysInKeySet(): void
    {
        [$firstRecipientKey, $firstRecipientKeyResource] = generateOpenSSLKey();
        $firstRecipient = generateX509Certificate($firstRecipientKey);

        [$secondRecipientKey, $secondRecipientKeyResource] = generateOpenSSLKey();
        $secondRecipient = generateX509Certificate($secondRecipientKey);

        $payload = buildExamplePayload();

        $firstJwe = buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($firstRecipient)
        );
        $secondJwe = buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($secondRecipient)
        );

        $jweDecryptService = new JweDecryptService(new JWKSet([
            getJwkFromResource($firstRecipientKeyResource),
            getJwkFromResource($secondRecipientKeyResource),
        ]));

        // Check if first jwe can be decrypted with key set
        $decryptedPayload = $jweDecryptService->decrypt($firstJwe);
        $this->assertEquals($payload, $decryptedPayload);

        // Check if second jwe can be decrypted with key set
        $decryptedPayload = $jweDecryptService->decrypt($secondJwe);
        $this->assertEquals($payload, $decryptedPayload);

        fclose($firstRecipientKeyResource);
        fclose($secondRecipientKeyResource);
    }
}
