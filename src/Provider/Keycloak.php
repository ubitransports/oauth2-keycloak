<?php

namespace Ubitransport\OAuth2\Client\Provider;

use Exception;
use Firebase\JWT\JWT;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Ubitransport\OAuth2\Client\Provider\Exception\EncryptionConfigurationException;

class Keycloak extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Keycloak URL, eg. http://localhost:8080/auth.
     */
    public ?string $authServerUrl = null;

    public ?string $realm = null;

    public ?string $encryptionAlgorithm = null;

    public ?string $encryptionKey = null;

    private ?AccessToken $adminAccessToken = null;

    public const METHOD_GET = 'GET';

    public const METHOD_POST = 'POST';

    public const METHOD_DELETE = 'DELETE';

    /**
     * Constructs an OAuth 2.0 service provider.
     *
     * @param array $options An array of options to set on this provider.
     *     Options include `clientId`, `clientSecret`, `redirectUri`, and `state`.
     *     Individual providers may introduce more options, as needed.
     * @param array $collaborators An array of collaborators that may be used to
     *     override this provider's default behavior. Collaborators include
     *     `grantFactory`, `requestFactory`, `httpClient`, and `randomFactory`.
     *     Individual providers may introduce more collaborators, as needed.
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (isset($options['encryptionKeyPath'])) {
            $this->setEncryptionKeyPath($options['encryptionKeyPath']);
            unset($options['encryptionKeyPath']);
        }
        parent::__construct($options, $collaborators);
    }

    /**
     * Attempts to decrypt the given response.
     *
     * @param string|array|null $response
     *
     * @return string|array|null
     * @throws EncryptionConfigurationException
     * @throws \JsonException
     */
    public function decryptResponse($response)
    {
        if (!is_string($response)) {
            return $response;
        }

        if ($this->usesEncryption()) {
            return json_decode(
                json_encode(
                    JWT::decode(
                        $response,
                        $this->encryptionKey,
                        array($this->encryptionAlgorithm)
                    ),
                    JSON_THROW_ON_ERROR
                ),
                true,
                512,
                JSON_THROW_ON_ERROR
            );
        }

        throw EncryptionConfigurationException::undeterminedEncryption();
    }

    /**
     * Get authorization url to begin OAuth flow
     *
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/auth';
    }

    /**
     * Get access token url to retrieve token
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/token';
    }

    /**
     * Get provider url to fetch user details
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/userinfo';
    }

    /**
     * Builds the logout URL.
     */
    public function getLogoutUrl(array $options = []): string
    {
        $base = $this->getBaseLogoutUrl();
        $params = $this->getAuthorizationParameters($options);
        $query = $this->getAuthorizationQuery($params);

        return $this->appendQuery($base, $query);
    }

    /**
     * Get logout url to logout of session token
     *
     * @return string
     */
    private function getBaseLogoutUrl(): string
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/logout';
    }

    /**
     * Creates base url from provider configuration.
     *
     * @return string
     */
    protected function getBaseUrlWithRealm(): string
    {
        return $this->authServerUrl.'/realms/'.$this->realm;
    }

    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return string[]
     */
    protected function getDefaultScopes(): array
    {
        return ['name', 'email'];
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * Check a provider response for errors.
     *
     * @param ResponseInterface $response
     * @param string|array      $data Parsed response data
     *
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['error'])) {
            $error = $data['error'].': '.$data['error_description'];
            throw new IdentityProviderException($error, 0, $data);
        }
    }

    /**
     * Generate a user object from a successful user details request.
     */
    protected function createResourceOwner(array $response, AccessToken $token): KeycloakResourceOwner
    {
        return new KeycloakResourceOwner($response);
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     */
    public function getResourceOwner(AccessToken $token): KeycloakResourceOwner
    {
        $response = $this->fetchResourceOwnerDetails($token);
        $response = $this->decryptResponse($response);

        return $this->createResourceOwner($response, $token);
    }

    /**
     * Updates expected encryption algorithm of Keycloak instance.
     *
     * @param string $encryptionAlgorithm
     *
     * @return Keycloak
     */
    public function setEncryptionAlgorithm($encryptionAlgorithm): Keycloak
    {
        $this->encryptionAlgorithm = $encryptionAlgorithm;

        return $this;
    }

    /**
     * Updates expected encryption key of Keycloak instance.
     *
     * @param string $encryptionKey
     *
     * @return Keycloak
     */
    public function setEncryptionKey($encryptionKey): Keycloak
    {
        $this->encryptionKey = $encryptionKey;

        return $this;
    }

    /**
     * Updates expected encryption key of Keycloak instance to content of given
     * file path.
     *
     * @param string $encryptionKeyPath
     *
     * @return Keycloak
     */
    public function setEncryptionKeyPath($encryptionKeyPath): Keycloak
    {
        try {
            $this->encryptionKey = file_get_contents($encryptionKeyPath);
        } catch (Exception $e) {
            // Not sure how to handle this yet.
        }

        return $this;
    }

    /**
     * Checks if provider is configured to use encryption.
     *
     * @return bool
     */
    public function usesEncryption(): bool
    {
        return (bool)$this->encryptionAlgorithm && $this->encryptionKey;
    }

    public function getCertificatePublicUrl(string $realm): string
    {
        return $this->authServerUrl.'/realms/'.$realm.'/protocol/openid-connect/certs';
    }

    public function getPathToIntrospectionEndPoint(string $realm): string
    {
        return $this->authServerUrl.'/realms/'.$realm.'/protocol/openid-connect/token/introspect';
    }

    public function getPathToDiscovery(string $realm): string
    {
        return $this->authServerUrl.'/realms/'.$realm.'/.well-known/openid-configuration';
    }

    public function getKeycloakOidcJson(string $realm, string $clientId): string
    {
        return $this->authServerUrl.'/realms/'.$realm.'/clients/'.$clientId.'/installation/providers/keycloak-oidc-keycloak-json';
    }

    public function getClients(string $realm)
    {
        return $this->authServerUrl.'/realms/'.$realm.'/clients';
    }

    public function getUsableAdminAccessToken(): AccessToken
    {
        return $this->adminAccessToken = $this->getUsableAccessToken($this->adminAccessToken);
    }

    public function getUsableAccessToken(AccessToken $token = null): AccessToken
    {
        if (null === $token) {
            return $this->getAccessTokenUsingClientCredentials();
        }

        $this->refreshTokenIfExpired($token);

        return $token;
    }

    public function getAccessTokenUsingClientCredentials(): AccessToken
    {
        try {
            return $this->getAccessToken('client_credentials');
        } catch (IdentityProviderException $e) {
        }
    }

    public function refreshTokenIfExpired(AccessToken &$token): void
    {
        if ($token->hasExpired()) {
            $token = $this->getAccessToken(
                'refresh_token',
                [
                    'refresh_token' => $token->getRefreshToken(),
                ]
            );
        }
    }

    public function sendAdminRequestToKeycloak(
        string $method,
        string $uri,
        array $options = []
    ): \Psr\Http\Message\ResponseInterface {
        $request = $this->getAuthenticatedRequest(
            $method,
            $this->getAuthServerUrl().$uri,
            $this->getUsableAdminAccessToken(),
            $options
        );

        return $this->getResponse($request);
    }

    /**
     * @return string
     */
    public function getAuthServerUrl(): ?string
    {
        return $this->authServerUrl;
    }
}
