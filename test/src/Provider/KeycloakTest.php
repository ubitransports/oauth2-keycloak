<?php

namespace
{
    $mockFileGetContents = null;
}

namespace Ubitransport\OAuth2\Client\Provider
{
    function file_get_contents()
    {
        global $mockFileGetContents;
        if (isset($mockFileGetContents) && ! is_null($mockFileGetContents)) {
            if (is_a($mockFileGetContents, 'Exception')) {
                throw $mockFileGetContents;
            }
            return $mockFileGetContents;
        } else {
            return call_user_func_array('\file_get_contents', func_get_args());
        }
    }
}

namespace Ubitransport\OAuth2\Client\Test\Provider
{
    use League\OAuth2\Client\Tool\QueryBuilderTrait;
    use Mockery as m;

    class KeycloakTest extends \PHPUnit_Framework_TestCase
    {
        use QueryBuilderTrait;

        protected \Ubitransport\OAuth2\Client\Provider\Keycloak $provider;

        protected function setUp(): void
        {
            $this->provider = new \Ubitransport\OAuth2\Client\Provider\Keycloak([
                'authServerUrl' => 'http://mock.url/auth',
                'realm' => 'mock_realm',
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_secret',
                'redirectUri' => 'none',
            ]);
        }

        public function tearDown()
        {
            m::close();
            parent::tearDown();
        }

        public function testAuthorizationUrl(): void
        {
            $url = $this->provider->getAuthorizationUrl();
            $uri = parse_url($url);
            parse_str($uri['query'], $query);

            $this->assertArrayHasKey('client_id', $query);
            $this->assertArrayHasKey('redirect_uri', $query);
            $this->assertArrayHasKey('state', $query);
            $this->assertArrayHasKey('scope', $query);
            $this->assertArrayHasKey('response_type', $query);
            $this->assertArrayHasKey('approval_prompt', $query);
            $this->assertNotNull($this->provider->getState());
        }

        public function testEncryptionAlgorithm(): void
        {
            $algorithm = uniqid('', true);
            $provider = new \Ubitransport\OAuth2\Client\Provider\Keycloak([
                'encryptionAlgorithm' => $algorithm,
            ]);

            $this->assertEquals($algorithm, $provider->encryptionAlgorithm);

            $algorithm = uniqid('', true);
            $provider->setEncryptionAlgorithm($algorithm);

            $this->assertEquals($algorithm, $provider->encryptionAlgorithm);
        }

        public function testEncryptionKey(): void
        {
            $key = uniqid('', true);
            $provider = new \Ubitransport\OAuth2\Client\Provider\Keycloak([
                'encryptionKey' => $key,
            ]);

            $this->assertEquals($key, $provider->encryptionKey);

            $key = uniqid('', true);
            $provider->setEncryptionKey($key);

            $this->assertEquals($key, $provider->encryptionKey);
        }

        public function testEncryptionKeyPath(): void
        {
            global $mockFileGetContents;
            $path = uniqid('', true);
            $key = uniqid('', true);
            $mockFileGetContents = $key;

            $provider = new \Ubitransport\OAuth2\Client\Provider\Keycloak([
                'encryptionKeyPath' => $path,
            ]);

            $this->assertEquals($key, $provider->encryptionKey);

            $path = uniqid('', true);
            $key = uniqid('', true);
            $mockFileGetContents = $key;

            $provider->setEncryptionKeyPath($path);

            $this->assertEquals($key, $provider->encryptionKey);
        }

        public function testEncryptionKeyPathFails(): void
        {
            global $mockFileGetContents;
            $path = uniqid('', true);
            $key = uniqid('', true);
            $mockFileGetContents = new \Exception();

            $provider = new \Ubitransport\OAuth2\Client\Provider\Keycloak([
                'encryptionKeyPath' => $path,
            ]);

            $provider->setEncryptionKeyPath($path);
        }

        public function testScopes(): void
        {
            $scopeSeparator = ',';
            $options = ['scope' => [uniqid('', true), uniqid('', true)]];
            $query = ['scope' => implode($scopeSeparator, $options['scope'])];
            $url = $this->provider->getAuthorizationUrl($options);
            $encodedScope = $this->buildQueryString($query);
            $this->assertContains($encodedScope, $url);
        }

        public function testGetAuthorizationUrl(): void
        {
            $url = $this->provider->getAuthorizationUrl();
            $uri = parse_url($url);

            $this->assertEquals('/auth/realms/mock_realm/protocol/openid-connect/auth', $uri['path']);
        }

        public function testGetLogoutUrl(): void
        {
            $url = $this->provider->getLogoutUrl();
            $uri = parse_url($url);

            $this->assertEquals('/auth/realms/mock_realm/protocol/openid-connect/logout', $uri['path']);
        }

        public function testGetBaseAccessTokenUrl(): void
        {
            $params = [];

            $url = $this->provider->getBaseAccessTokenUrl($params);
            $uri = parse_url($url);

            $this->assertEquals('/auth/realms/mock_realm/protocol/openid-connect/token', $uri['path']);
        }

        public function testGetAccessToken(): void
        {
            $response = m::mock('Psr\Http\Message\ResponseInterface');
            $response->shouldReceive('getBody')->andReturn('{"access_token":"mock_access_token", "scope":"email", "token_type":"bearer"}');
            $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

            $client = m::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')->times(1)->andReturn($response);
            $this->provider->setHttpClient($client);

            $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

            $this->assertEquals('mock_access_token', $token->getToken());
            $this->assertNull($token->getExpires());
            $this->assertNull($token->getRefreshToken());
            $this->assertNull($token->getResourceOwnerId());
        }

        public function testUserData(): void
        {
            $userId = random_int(1000,9999);
            $name = uniqid('', true);
            $nickname = uniqid('', true);
            $email = uniqid('', true);

            $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $postResponse->shouldReceive('getBody')->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');
            $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);

            $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $userResponse->shouldReceive('getBody')->andReturn('{"sub": '.$userId.', "name": "'.$name.'", "email": "'.$email.'"}');
            $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

            $client = m::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')
                ->times(2)
                ->andReturn($postResponse, $userResponse);
            $this->provider->setHttpClient($client);

            $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
            $user = $this->provider->getResourceOwner($token);

            $this->assertEquals($userId, $user->getId());
            $this->assertEquals($userId, $user->toArray()['sub']);
            $this->assertEquals($name, $user->getName());
            $this->assertEquals($name, $user->toArray()['name']);
            $this->assertEquals($email, $user->getEmail());
            $this->assertEquals($email, $user->toArray()['email']);
        }

        public function testUserDataWithEncryption(): void
        {
            $userId = random_int(1000,9999);
            $name = uniqid('', true);
            $nickname = uniqid('', true);
            $email =uniqid('', true);
            $jwt = uniqid('', true);
            $algorithm = uniqid('', true);
            $key = uniqid('', true);

            $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $postResponse->shouldReceive('getBody')->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');
            $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
            $postResponse->shouldReceive('getStatusCode')->andReturn(200);

            $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $userResponse->shouldReceive('getBody')->andReturn($jwt);
            $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/jwt']);
            $userResponse->shouldReceive('getStatusCode')->andReturn(200);

            $decoder = \Mockery::mock('overload:Firebase\JWT\JWT');
            $decoder->shouldReceive('decode')->with($jwt, $key, [$algorithm])->andReturn([
                'sub' => $userId,
                'email' => $email,
                'name' => $name,
            ]);

            $client = m::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')
                ->times(2)
                ->andReturn($postResponse, $userResponse);
            $this->provider->setHttpClient($client);

            $token = $this->provider->setEncryptionAlgorithm($algorithm)
                ->setEncryptionKey($key)
                ->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
            $user = $this->provider->getResourceOwner($token);

            $this->assertEquals($userId, $user->getId());
            $this->assertEquals($userId, $user->toArray()['sub']);
            $this->assertEquals($name, $user->getName());
            $this->assertEquals($name, $user->toArray()['name']);
            $this->assertEquals($email, $user->getEmail());
            $this->assertEquals($email, $user->toArray()['email']);
        }

        /**
         * @expectedException Ubitransport\OAuth2\Client\Provider\Exception\EncryptionConfigurationException
         */
        public function testUserDataFailsWhenEncryptionEncounteredAndNotConfigured(): void
        {
            $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $postResponse->shouldReceive('getBody')->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');
            $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
            $postResponse->shouldReceive('getStatusCode')->andReturn(200);

            $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $userResponse->shouldReceive('getBody')->andReturn(uniqid('', true));
            $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/jwt']);
            $userResponse->shouldReceive('getStatusCode')->andReturn(200);

            $client = m::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')
                ->times(2)
                ->andReturn($postResponse, $userResponse);
            $this->provider->setHttpClient($client);

            $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
            $user = $this->provider->getResourceOwner($token);
        }

        /**
         * @expectedException League\OAuth2\Client\Provider\Exception\IdentityProviderException
         */
        public function testErrorResponse(): void
        {
            $response = m::mock('Psr\Http\Message\ResponseInterface');
            $response->shouldReceive('getBody')->andReturn('{"error": "invalid_grant", "error_description": "Code not found"}');
            $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

            $client = m::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')->times(1)->andReturn($response);
            $this->provider->setHttpClient($client);

            $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        }
    }
}
