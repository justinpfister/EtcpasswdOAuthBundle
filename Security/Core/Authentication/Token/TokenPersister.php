<?php
namespace Etcpasswd\OAuthBundle\Security\Core\Authentication\Token;

use Symfony\Component\HttpFoundation\Session;

use Etcpasswd\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

class TokenPersister
{
    protected $sessionKey;
    protected $session;

    public function __construct($sessionKey, Session $session)
    {
        $this->session = $session;
        $this->sessionKey = $sessionKey;
    }

    public function get()
    {
        return $this->session->get($this->sessionKey);
        //return $this->session->getFlash($this->sessionKey);
    }

    public function set(OpenIdToken $token)
    {
        $this->session->set($this->sessionKey, $token);
        //$this->session->setFlash($this->sessionKey, $token);
    }
}
