<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\OpenIDConfiguration;

use Exception;
use Throwable;

class OpenIDConfigurationLoaderException extends Exception
{
    /**
     * @var array<string, mixed>
     */
    protected array $context;

    /**
     * @param string $message
     * @param int $code
     * @param Throwable|null $previous
     * @param array<string, mixed> $context
     */
    public function __construct(
        string $message = "",
        int $code = 0,
        ?Throwable $previous = null,
        array $context = [],
    ) {
        parent::__construct($message, $code, $previous);

        $this->context = $context;
    }

    /**
     * Get the exception's context information.
     *
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return $this->context;
    }
}
