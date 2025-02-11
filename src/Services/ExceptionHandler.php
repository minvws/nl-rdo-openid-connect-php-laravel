<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services;

use Exception;
use Illuminate\Http\Request;
use Jumbojett\OpenIDConnectClientException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;

class ExceptionHandler implements ExceptionHandlerInterface
{
    public function __construct(
        protected ?LoggerInterface $logger = null,
    ) {
    }

    public function handleExceptionWhileAuthenticate(OpenIDConnectClientException $exception): Response
    {
        if (str_starts_with($exception->getMessage(), 'Error: ')) {
            return $this->handleRequestError($exception);
        }

        if ($exception->getMessage() === 'Unable to determine state') {
            return $this->handleUnableToDetermineState($exception);
        }

        $this->logger?->error('OIDC Exception occurred while authenticating', [
            'exception' => $exception,
        ]);
        return $this->defaultResponse($exception);
    }

    /**
     * Called when request to userinfo endpoint fails, jwt signature is invalid, or userinfo is not an object.
     * @param OpenIDConnectClientException $exception
     * @return Response
     */
    public function handleExceptionWhileRequestUserInfo(OpenIDConnectClientException $exception): Response
    {
        $this->logger?->error('OIDC Exception occurred while requesting user info', [
            'exception' => $exception,
        ]);

        return $this->defaultResponse($exception);
    }

    public function handleException(Exception $exception): Response
    {
        $this->logger?->error('OIDC Generic exception occurred', [
            'exception' => $exception,
        ]);

        return $this->defaultResponseGenericException($exception);
    }

    /**
     * Called when url contains query parameter error.
     * For example user is sent back from idp with error=login_cancelled.
     * @param OpenIDConnectClientException $exception
     * @return Response
     */
    protected function handleRequestError(OpenIDConnectClientException $exception): Response
    {
        $this->logger?->debug('OIDC Request error', [
            'exception' => $exception,
            'query' => $this->getRequest()?->query->all(),
        ]);

        return $this->default400Response($exception);
    }

    /**
     * Called when url contains query parameter code and state, and state does not match with the value from session.
     * @param OpenIDConnectClientException $exception
     * @return Response
     */
    protected function handleUnableToDetermineState(OpenIDConnectClientException $exception): Response
    {
        $this->logger?->debug('OIDC State in url does not match with session', [
            'exception' => $exception,
        ]);

        return $this->default400Response($exception);
    }

    protected function defaultResponse(OpenIDConnectClientException $exception): Response
    {
        abort(500, $exception->getMessage());
    }

    protected function defaultResponseGenericException(Exception $exception): Response
    {
        abort(500, $exception->getMessage());
    }

    protected function default400Response(OpenIDConnectClientException $exception): Response
    {
        abort(400, $exception->getMessage());
    }

    protected function getRequest(): ?Request
    {
        /** @psalm-var Request $request */
        $request = request();
        return $request;
    }
}
