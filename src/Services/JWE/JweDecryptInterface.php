<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services\JWE;

interface JweDecryptInterface
{
    public function decrypt(string $jweString): string;
}
