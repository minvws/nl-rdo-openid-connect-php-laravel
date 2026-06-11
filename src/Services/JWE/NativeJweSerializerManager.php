<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services\JWE;

use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;

final class NativeJweSerializerManager implements JweSerializerManagerInterface
{
    public function __construct(
        private JWESerializerManager $manager = new JWESerializerManager([new CompactSerializer()]),
    ) {
    }

    #[\Override]
    public function unserialize(string $input): JWE
    {
        return $this->manager->unserialize($input);
    }
}
