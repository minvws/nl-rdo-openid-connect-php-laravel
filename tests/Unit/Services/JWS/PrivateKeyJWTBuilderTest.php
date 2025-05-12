<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Unit\Services\JWS;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\Serializer;
use MinVWS\OpenIDConnectLaravel\Services\JWS\PrivateKeyJWTBuilder;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function MinVWS\OpenIDConnectLaravel\Tests\{
    generateInsecureOpenSSLKey,
    getJwkFromResource,
};

class PrivateKeyJWTBuilderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected OpenSSLAsymmetricKey $privateKey;
    protected $privateKeyResource;
    protected string $publicKey;
    protected AlgorithmManager $algorithmManager;
    protected int $tokenLifetimeInSeconds = 60;

    protected function setUp(): void
    {
        parent::setUp();

        [$privateKey, $privateKeyResource] = generateInsecureOpenSSLKey();

        $this->privateKey = $privateKey;
        $this->privateKeyResource = $privateKeyResource;
        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];

        $this->algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);
    }

    protected function tearDown(): void
    {
        if (is_resource($this->privateKeyResource)) {
            fclose($this->privateKeyResource);
        }

        parent::tearDown();
    }

    public function testPayload(): void
    {
        $mockSerializer = Mockery::mock(Serializer::class);
        $mockSerializer
            ->shouldReceive('serialize')
            ->withArgs(function ($jws, $index) {
                /** @var JWS $jws */
                $this->assertInstanceOf(JWS::class, $jws);
                $this->assertSame(0, $index);

                $payload = json_decode($jws->getPayload(), true);

                $iat = $payload['iat'];
                $this->assertSame($iat + $this->tokenLifetimeInSeconds, $payload['exp']);

                $this->assertSame('client_id', $payload['iss']);
                $this->assertSame('client_id', $payload['sub']);
                $this->assertSame('audience', $payload['aud']);
                $this->assertNotEmpty($payload['jti']);

                return true;
            });

        $builder = new PrivateKeyJWTBuilder(
            'client_id',
            new JWSBuilder($this->algorithmManager),
            getJwkFromResource($this->privateKeyResource),
            'RS256',
            $mockSerializer,
            $this->tokenLifetimeInSeconds,
        );

        $builder->__invoke('audience');
    }

    public function testSignature(): void
    {
        // Build JWS
        $buildJws = $this->generateJws('client_id', 'audience');

        // Unserialize the JWS string to JWS
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);
        $jws = $serializerManager->unserialize($buildJws);

        // Create the public JWK from the public key
        $publicJwk = JWKFactory::createFromKey($this->publicKey);

        // Verify the JWS with the public key
        $jwsVerifier = new JWSVerifier($this->algorithmManager);
        $isVerified = $jwsVerifier->verifyWithKey($jws, $publicJwk, 0);

        $this->assertTrue($isVerified);
    }

    protected function generateJws(string $clientId, string $audience): string
    {
        $builder = new PrivateKeyJWTBuilder(
            $clientId,
            new JWSBuilder($this->algorithmManager),
            getJwkFromResource($this->privateKeyResource),
            'RS256',
            new CompactSerializer(),
            $this->tokenLifetimeInSeconds,
        );

        return $builder->__invoke($audience);
    }
}
