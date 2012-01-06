<?php

namespace Etcpasswd\OAuthBundle\Provider;


use Buzz\Client\ClientInterface,
    Buzz\Message\Request,
    Buzz\Message\Response;

use Symfony\Component\HttpFoundation\Session;

/**
 *
 * @author   Marcel Beerta <marcel@etcpasswd.de>
 */
abstract class Provider implements ProviderInterface
{
    protected $client;
    protected $session;

    public function __construct(ClientInterface $client, Session $session)
    {
        $this->client = $client;
        $this->session = $session;
    }

    protected function request($url, $method = null)
    {
        $method = is_null($method) ? Request::METHOD_GET : $method;
        $request = new Request($method, $url);
        $response = new Response();
        $this->client->send($request, $response);
        return $response->getContent();
    }

}