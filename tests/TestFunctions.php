<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use JsonException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RuntimeException;

function buildJweString(string $payload, JWK $recipient): string
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
function buildExamplePayload(): string
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
function generateOpenSSLKey(): array
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
function generateX509Certificate(OpenSSLAsymmetricKey $key): OpenSSLCertificate
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

/**
 * Get JWK from resource
 * @param $resource resource
 * @return JWK
 */
function getJwkFromResource($resource): JWK
{
    if (!is_resource($resource)) {
        throw new RuntimeException('Could not create temporary file');
    }

    return JWKFactory::createFromKeyFile(stream_get_meta_data($resource)['uri']);
}
