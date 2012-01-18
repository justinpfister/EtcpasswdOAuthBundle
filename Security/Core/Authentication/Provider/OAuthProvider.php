<?php

namespace Etcpasswd\OAuthBundle\Security\Core\Authentication\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface,
    Symfony\Component\Security\Core\Exception\AuthenticationException,
    Symfony\Component\Security\Core\Authentication\Token\TokenInterface,
    Symfony\Component\Security\Core\User\UserCheckerInterface,
    Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface,
    Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;



use Etcpasswd\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

/**
 * @author   Marcel Beerta <marcel@etcpasswd.de>
 */
class OAuthProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $userChecker;
    private $providerKey;
    private $encoderFactory;

    public function __construct(UserProviderInterface $userProvider, $providerKey)
    {
        $this->userProvider     = $userProvider;
        $this->providerKey      = $providerKey;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername(),true); //true references auto-login functionality for username references coming from validated sources.
        if ($user) {
            //$authenticatedToken = new OAuthtoken($user->getRoles(), $token->getResponse());

            // Since we're only doing basic authorization.. and not using any additional services from the OAuth provider.
            $authenticatedToken = new UsernamePasswordToken($user, null, $this->providerKey, $user->getRoles());
            //$authenticatedToken ->setAuthenticated(true);
            $authenticatedToken ->setUser($user);
            return $authenticatedToken;
        }

        throw new AuthenticationException('OAuth Authentication Failed.');
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken;
    }

}