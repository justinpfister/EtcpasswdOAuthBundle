<?php

namespace Etcpasswd\OAuthBundle\Provider\Token;

/**
 *
 * @author   Marcel Beerta <marcel@etcpasswd.de>
 */
class YahooToken implements TokenResponseInterface
{

    private $json;
    private $accessToken;
    private $expiresAt;

    /**
     * Constructs a new token
     *
     * @param object $jsonObject  Json object
     * @param string $accessToken Api access token
     *
     * @return void
     */
    public function __construct($jsonObject, $accessToken, $expiresAt)
    {
        $this->json = $jsonObject;
        $this->accessToken = $accessToken;
        $this->expiresAt = $expiresAt;
    }

    /**
     * {@inheritDoc}
     */
    public function getExpires()
    {
        return $this->expiresAt;
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername($field = 'displayName')
    {
        //multiple email addresses .. find Primary!
        if(is_array($this->json->query->results->profile->emails)) {
         foreach( $this->json->query->results->profile->emails as $email) {
          if($email->primary == 'true') return $email->handle;
         }
        }

        // single email -- bring it!
        return $this->json->query->results->profile->emails->handle;
     }

    /**
     * {@inheritDoc}
     */
    public function isLongLived()
    {
        return false;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function getProviderKey()
    {
        return 'yahoo';
    }
}