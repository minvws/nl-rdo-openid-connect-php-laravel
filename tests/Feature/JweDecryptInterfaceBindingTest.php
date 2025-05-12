<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Feature;

use Jose\Component\KeyManagement\JWKFactory;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptInterface;
use MinVWS\OpenIDConnectLaravel\Tests\TestCase;
use OpenSSLCertificate;

use function MinVWS\OpenIDConnectLaravel\Tests\{
    generateInsecureOpenSSLKey,
    generateX509Certificate,
    buildJweString,
    buildExamplePayload
};

class JweDecryptInterfaceBindingTest extends TestCase
{
    /**
     * @var resource
     */
    protected $decryptionKeyResource;
    protected OpenSSLCertificate $recipient;


    public function setUp(): void
    {
        [$key, $keyResource] = generateInsecureOpenSSLKey();
        $this->decryptionKeyResource = $keyResource;
        $this->recipient = generateX509Certificate($key);

        parent::setUp();
    }

    /**
     * @throws \JsonException
     */
    public function testJweDecrypter(): void
    {
        $payload = buildExamplePayload();

        $jwe = buildJweString(
            payload: $payload,
            recipient: JWKFactory::createFromX509Resource($this->recipient)
        );

        $decrypter = $this->app->make(JweDecryptInterface::class);
        $decryptedData = $decrypter->decrypt($jwe);

        $this->assertSame($payload, $decryptedData);
    }


    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('oidc.decryption_key_path', stream_get_meta_data($this->decryptionKeyResource)['uri']);
    }
}
