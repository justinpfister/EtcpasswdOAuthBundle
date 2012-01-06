<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\YahooToken;

use Buzz\Message\Request,
    Buzz\Message\Response;
/**
 *
 * @author   Marcel Beerta <marcel@etcpasswd.de>
 */
class YahooProvider extends Provider
{

    public function createTokenResponse($clientId, $secret, $returnvalues, $redirectUrl = "", $service = null)
    {

        $url = 'https://api.login.yahoo.com/oauth/v2/get_token';

        $request = new Request(Request::METHOD_POST, $url);
        $request->setContent(http_build_query(array(
            'oauth_consumer_key'     => $clientId,
            'oauth_signature_method' => 'plaintext',
            'oauth_nonce' => 43409803434,
            'oauth_signature' => $secret . '&',
            'oauth_timestamp'          => time(),
            'oauth_verifier'        => $returnvalues['oauth_verifier'],
            'oauth_version'    => '1.0',
            'oauth_token'   => $returnvalues['oauth_token'],
        )));

        $response = new Response();
        $this->client->send($request, $response);

        print_r($response);
        exit;

        $data = json_decode($response->getContent());
        if (isset($data->error)) {
            return;
        }
        $expiresAt = time()+$data->expires_in;

        $people = (is_null($service))? 'https://www.googleapis.com/plus/v1/people/me' : $service
            .'?key='.$clientId
            .'&access_token='.$data->access_token;
        $request = new Request(Request::METHOD_GET, $people);
        $response = new Response();

        $this->client->send($request, $response);
        $me = json_decode($response->getContent());

        return new YahooToken($me, $data->access_token, $expiresAt);
    }

    public function getAuthorizationUrl($clientId, $scope, $redirectUrl, $secret)
    {

        $url = 'https://api.login.yahoo.com/oauth/v2/get_request_token';

                $request = new Request(Request::METHOD_POST, $url);
                $request->setContent(http_build_query(array(
                    'oauth_nonce' => 434098098,
                    'oauth_timestamp'          => time(),
                    'oauth_consumer_key'     => $clientId,
                    'oauth_signature_method' => 'plaintext',
                    'oauth_signature' => $secret . '&',
                    'oauth_version'    => '1.0',
                    'oauth_callback'  => urldecode($redirectUrl)
                )));

        $response = new Response();
        $this->client->send($request, $response);
        $data = json_decode($response->getContent());

        parse_str($response->getContent(),$output);

        return 'https://api.login.yahoo.com/oauth/v2/request_auth'
            .'?oauth_token='.$output['oauth_token'];
    }

}