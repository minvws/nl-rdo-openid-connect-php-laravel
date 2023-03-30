<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Unit\Services\JWE;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;
use JsonException;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptException;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptService;
use Mockery;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class JweDecryptServiceTest extends TestCase
{
    /**
     * @var resource
     */
    protected $decryptionKeyResource;
    protected JWK $decryptionKey;
    protected OpenSSLCertificate $x509Certificate;

    protected function setUp(): void
    {
        parent::setUp();

        [$key, $keyResource] = $this->generateOpenSSLKey();
        $this->decryptionKeyResource = $keyResource;
        $this->decryptionKey = JWKFactory::createFromKeyFile(stream_get_meta_data($keyResource)['uri']);
        $this->x509Certificate = $this->generateX509Certificate($key);
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
        $jweDecryptService = new JweDecryptService($this->decryptionKey);

        $this->assertInstanceOf(JweDecryptService::class, $jweDecryptService);
    }

    /**
     * @throws JweDecryptException
     * @throws JsonException
     */
    public function testJweDecryption(): void
    {
        $payload = $this->buildExamplePayload();

        $jwe = $this->buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($this->x509Certificate)
        );

        $jweDecryptService = new JweDecryptService($this->decryptionKey);
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
        [$key, $keyResource] = $this->generateOpenSSLKey();
        $jwk = JWKFactory::createFromKeyFile(stream_get_meta_data($keyResource)['uri']);

        // Build JWE for default certificate
        $payload = $this->buildExamplePayload();
        $jwe = $this->buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($this->x509Certificate)
        );

        // Try to decrypt with different key
        $jweDecryptService = new JweDecryptService($jwk);
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

        $decryptionKey = Mockery::mock(JWK::class);
        $serializerManager = Mockery::mock(JWESerializerManager::class);
        $serializerManager
            ->shouldReceive('unserialize')
            ->with('something')
            ->andReturn($jweMock);

        $jweDecrypter = Mockery::mock(JWEDecrypter::class);
        $jweDecrypter
            ->shouldReceive('decryptUsingKey')
            ->andReturn(true);

        $decryptService = new JweDecryptService(
            $decryptionKey,
            $serializerManager,
            $jweDecrypter,
        );

        $decryptService->decrypt('something');
    }

    protected function buildJweString(string $payload, JWK $recipient): string
    {
        // Create the JWE builder object
        $jweBuilder = new JWEBuilder(
            new AlgorithmManager([new RSAOAEP()]),
            new AlgorithmManager([new A128CBCHS256()]),
            new CompressionMethodManager([new Deflate()])
        );

        // Build the JWE
        $jwe = $jweBuilder
            ->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP',
                'enc' => 'A128CBC-HS256',
                'zip' => 'DEF',
            ])
            ->addRecipient($recipient)
            ->build();

        // Get the compact serialization of the JWE
        return (new CompactSerializer())->serialize($jwe, 0);
    }

    /**
     * @throws JsonException
     */
    protected function buildExamplePayload(): string
    {
        return json_encode([
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 3600,
            'iss' => 'My service',
            'aud' => 'Your application',
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Generate OpenSSL Key and return the tempfile resource
     * @return array{OpenSSLAsymmetricKey, resource}
     */
    protected function generateOpenSSLKey(): array
    {
        $file = tmpfile();
        if (!is_resource($file)) {
            throw new RuntimeException('Could not create temporary file');
        }

        $key = openssl_pkey_new([
            'private_key_bits' => 512,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Could not generate private key');
        }

        openssl_pkey_export($key, $privateKey);
        fwrite($file, $privateKey);

        return [$key, $file];
    }

    /**
     * Generate X509 certificate
     * @param OpenSSLAsymmetricKey $key
     * @return OpenSSLCertificate
     */
    protected function generateX509Certificate(OpenSSLAsymmetricKey $key): OpenSSLCertificate
    {
        $csr = openssl_csr_new([], $key);
        if (!$csr instanceof OpenSSLCertificateSigningRequest) {
            throw new RuntimeException('Could not generate CSR');
        }

        $certificate = openssl_csr_sign($csr, null, $key, 365);
        if (!$certificate instanceof OpenSSLCertificate) {
            throw new RuntimeException('Could not generate X509 certificate');
        }

        return $certificate;
    }
}
