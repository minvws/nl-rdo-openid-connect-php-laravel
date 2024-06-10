<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services\JWS;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JWSSerializer;

class PrivateKeyJWTBuilder
{
    public function __construct(
        protected string $clientId,
        protected JWSBuilder $jwsBuilder,
        protected JWK $signatureKey,
        protected string $signatureAlgorithm,
        protected JWSSerializer $serializer,
        protected int $tokenLifetimeInSeconds,
    ) {
    }

    public function __invoke(string $audience): string
    {
        return $this->buildJws($this->getPayload($audience));
    }

    protected function getPayload(string $audience): string
    {
        $jti = hash('sha256', bin2hex(random_bytes(64)));
        $now = time();

        return json_encode([
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'aud' => $audience,
            'jti' => $jti,
            'exp' => $now + $this->tokenLifetimeInSeconds,
            'iat' => $now,
        ], JSON_THROW_ON_ERROR);
    }

    protected function buildJws(string $payload): string
    {
        $jws = $this->jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($this->signatureKey, ['alg' => $this->signatureAlgorithm])
            ->build();

        return $this->serializer->serialize($jws, 0);
    }
}
