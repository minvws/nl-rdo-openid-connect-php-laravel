<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Unit\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\Http\Controllers\LoginController;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseHandler;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseHandlerInterface;
use MinVWS\OpenIDConnectLaravel\OpenIDConnectClient;
use MinVWS\OpenIDConnectLaravel\Services\ExceptionHandlerInterface;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptException;
use MinVWS\OpenIDConnectLaravel\Services\ExceptionHandler;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;

class LoginControllerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    public function testLoginControllerCanBeCreated(): void
    {
        $loginController = new LoginController(
            new OpenIDConnectClient(),
            new ExceptionHandler(),
            new LoginResponseHandler(),
        );
        $this->assertInstanceOf(LoginController::class, $loginController);
    }

    public function testExceptionHandlerIsCalledWhenAuthenticateThrowsException(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('setLoginHint')
            ->once();
        $mockClient
            ->shouldReceive('authenticate')
            ->andThrow(OpenIDConnectClientException::class);

        $mockExceptionHandler = Mockery::mock(ExceptionHandlerInterface::class);
        $mockExceptionHandler
            ->shouldReceive('handleExceptionWhileAuthenticate')
            ->once();

        $mockLoginResponseHandler = Mockery::mock(LoginResponseHandlerInterface::class);
        $mockLoginResponseHandler->shouldNotHaveBeenCalled();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
            $mockLoginResponseHandler,
        );

        $loginController->__invoke(new Request());
    }

    public function testExceptionHandlerIsCalledWhenRequestUserInfoDoesNotReturnAnObject(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('setLoginHint')
            ->once();
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andReturn('not an object')
            ->once();

        $mockExceptionHandler = Mockery::mock(ExceptionHandlerInterface::class);
        $mockExceptionHandler
            ->shouldReceive('handleExceptionWhileRequestUserInfo')
            ->withArgs(function (OpenIDConnectClientException $e) {
                return $e->getMessage() === 'Received user info is not an object';
            })
            ->once();

        $mockLoginResponseHandler = Mockery::mock(LoginResponseHandlerInterface::class);
        $mockLoginResponseHandler->shouldNotHaveBeenCalled();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
            $mockLoginResponseHandler,
        );

        $loginController->__invoke(new Request());
    }

    public function testExceptionHandlerIsCalledWhenRequestUserInfoThrowsAnException(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('setLoginHint')
            ->once();
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andThrow(OpenIDConnectClientException::class, 'Something went wrong')
            ->once();

        $mockExceptionHandler = Mockery::mock(ExceptionHandlerInterface::class);
        $mockExceptionHandler
            ->shouldReceive('handleExceptionWhileRequestUserInfo')
            ->withArgs(function (OpenIDConnectClientException $e) {
                return $e->getMessage() === 'Something went wrong';
            })
            ->once();

        $mockLoginResponseHandler = Mockery::mock(LoginResponseHandlerInterface::class);
        $mockLoginResponseHandler->shouldNotHaveBeenCalled();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
            $mockLoginResponseHandler,
        );

        $loginController->__invoke(new Request());
    }

    public function testExceptionHandlerIsCalledWhenRequestUserInfoThrowsAnJweDecryptException(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('setLoginHint')
            ->once();
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andThrow(JweDecryptException::class, 'Something went wrong')
            ->once();

        $mockExceptionHandler = Mockery::mock(ExceptionHandlerInterface::class);
        $mockExceptionHandler
            ->shouldReceive('handleException')
            ->withArgs(function (Exception $e) {
                return $e->getMessage() === 'Something went wrong';
            })
            ->once();

        $mockLoginResponseHandler = Mockery::mock(LoginResponseHandlerInterface::class);
        $mockLoginResponseHandler->shouldNotHaveBeenCalled();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
            $mockLoginResponseHandler,
        );

        $loginController->__invoke(new Request());
    }

    public function testResponseIsReturned(): void
    {
        $userInfo = $this->exampleUserInfo();

        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('setLoginHint')
            ->once();
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andReturn($userInfo)
            ->once();

        $mockExceptionHandler = Mockery::mock(ExceptionHandler::class);
        $mockExceptionHandler->shouldNotHaveBeenCalled();

        $mockLoginResponseHandler = Mockery::mock(LoginResponseHandlerInterface::class);
        $mockLoginResponseHandler
            ->shouldReceive('handleLoginResponse')
            ->once()
            ->andReturn(new JsonResponse([
                'userInfo' => $userInfo,
            ]));

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
            $mockLoginResponseHandler,
        );

        $response = $loginController->__invoke(new Request());

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(json_encode([
            'userInfo' => $userInfo,
        ]), $response->getContent());
    }

    protected function exampleUserInfo(): object
    {
        return (object) [
            'sub' => '1234567890',
            'name' => 'John Doe',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'middle_name' => 'Middle',
            'nickname' => 'JD',
            'preferred_username' => 'johndoe',
            'email' => '',
        ];
    }
}
