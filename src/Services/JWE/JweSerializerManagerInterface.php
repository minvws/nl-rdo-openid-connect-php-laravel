<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services\JWE;

use Jose\Component\Encryption\JWE;

interface JweSerializerManagerInterface
{
    public function unserialize(string $input): JWE;
}
