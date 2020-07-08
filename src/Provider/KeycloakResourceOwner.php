<?php

namespace Ubitransport\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface
{
    protected array $response;

    public function __construct(array $response = [])
    {
        $this->response = $response;
    }

    /**
     * Get resource owner id
     */
    public function getId(): ?string
    {
        return $this->response['sub'] ?: null;
    }

    /**
     * Get resource owner email
     */
    public function getEmail(): ?string
    {
        return $this->response['email'] ?: null;
    }

    /**
     * Get resource owner name
     */
    public function getName(): ?string
    {
        return $this->response['name'] ?: null;
    }

    /**
     * Return all of the owner details available as an array.
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
