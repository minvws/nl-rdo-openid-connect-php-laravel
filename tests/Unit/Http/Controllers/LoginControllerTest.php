<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Unit\Http\Controllers;

use Exception;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\Http\Controllers\LoginController;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponse;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseInterface;
use MinVWS\OpenIDConnectLaravel\OpenIDConnectClient;
use MinVWS\OpenIDConnectLaravel\Services\JWE\JweDecryptException;
use MinVWS\OpenIDConnectLaravel\Services\OpenIDConnectExceptionHandler;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

class LoginControllerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        parent::setUp();

        // Bind the LoginResponseInterface to the LoginResponse class
        app()->bind(LoginResponseInterface::class, LoginResponse::class);
    }

    protected function tearDown(): void
    {
        // Flush so the LoginResponseInterface binding is removed
        app()->flush();

        parent::tearDown();
    }

    public function testLoginControllerCanBeCreated(): void
    {
        $loginController = new LoginController(
            new OpenIDConnectClient(),
            new OpenIDConnectExceptionHandler(),
        );
        $this->assertInstanceOf(LoginController::class, $loginController);
    }

    public function testExceptionHandlerIsCalledWhenAuthenticateThrowsException(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient
            ->shouldReceive('authenticate')
            ->andThrow(OpenIDConnectClientException::class);

        $mockExceptionHandler = Mockery::mock(OpenIDConnectExceptionHandler::class);
        $mockExceptionHandler
            ->shouldReceive('handleExceptionWhileAuthenticate')
            ->once();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
        );

        $loginController->__invoke();
    }

    public function testExceptionHandlerIsCalledWhenRequestUserInfoDoesNotReturnAnObject(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andReturn('not an object')
            ->once();

        $mockExceptionHandler = Mockery::mock(OpenIDConnectExceptionHandler::class);
        $mockExceptionHandler
            ->shouldReceive('handleExceptionWhileRequestUserInfo')
            ->withArgs(function (OpenIDConnectClientException $e) {
                return $e->getMessage() === 'Received user info is not an object';
            })
            ->once();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
        );

        $loginController->__invoke();
    }

    public function testExceptionHandlerIsCalledWhenRequestUserInfoThrowsAnException(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andThrow(OpenIDConnectClientException::class, 'Something went wrong')
            ->once();

        $mockExceptionHandler = Mockery::mock(OpenIDConnectExceptionHandler::class);
        $mockExceptionHandler
            ->shouldReceive('handleExceptionWhileRequestUserInfo')
            ->withArgs(function (OpenIDConnectClientException $e) {
                return $e->getMessage() === 'Something went wrong';
            })
            ->once();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
        );

        $loginController->__invoke();
    }

    public function testExceptionHandlerIsCalledWhenRequestUserInfoThrowsAnJweDecryptException(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andThrow(JweDecryptException::class, 'Something went wrong')
            ->once();

        $mockExceptionHandler = Mockery::mock(OpenIDConnectExceptionHandler::class);
        $mockExceptionHandler
            ->shouldReceive('handleException')
            ->withArgs(function (Exception $e) {
                return $e->getMessage() === 'Something went wrong';
            })
            ->once();

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
        );

        $loginController->__invoke();
    }

    public function testLoginResponseIsReturnedWithUserInfo(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andReturn($this->exampleUserInfo())
            ->once();

        $mockExceptionHandler = Mockery::mock(OpenIDConnectExceptionHandler::class);

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
        );

        $response = $loginController->__invoke();

        $this->assertInstanceOf(LoginResponseInterface::class, $response);
        $this->assertInstanceOf(Responsable::class, $response);
    }

    public function testUserInfoIsReturned(): void
    {
        $mockClient = Mockery::mock(OpenIDConnectClient::class);
        $mockClient->shouldReceive('authenticate')->once();
        $mockClient
            ->shouldReceive('requestUserInfo')
            ->andReturn($this->exampleUserInfo())
            ->once();

        $mockExceptionHandler = Mockery::mock(OpenIDConnectExceptionHandler::class);

        $loginController = new LoginController(
            $mockClient,
            $mockExceptionHandler,
        );

        $loginResponse = $loginController->__invoke();
        $response = $loginResponse->toResponse(Mockery::mock(Request::class));

        $this->assertSame(json_encode([
            'userInfo' => $this->exampleUserInfo(),
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
