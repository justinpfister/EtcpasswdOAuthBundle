<?php

namespace Etcpasswd\OAuthBundle\Provider;

use Etcpasswd\OAuthBundle\Provider\Token\YahooToken;
use OAuth;

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
        $nonce = mt_rand();

        $params =  'oauth_consumer_key='. $clientId
                . '&oauth_nonce=' . $nonce
                . '&oauth_signature_method=' . 'hmac-sha1'
                . '&oauth_timestamp='. time()
                . '&oauth_token=' .$returnvalues['oauth_token']
                . '&oauth_verifier=' . $returnvalues['oauth_verifier']
                . '&oauth_version=' .'1.0';

        $signature_base = 'POST' . '&' . rawurlencode($url) . '&' . rawurlencode($params);
        $signature_key = rawurlencode($secret) . '&' . rawurlencode($this->session->get('yahoo.oauth_token_secret'));

        $sig = base64_encode(hash_hmac('sha1', $signature_base, $signature_key,true));

            $request = new Request(Request::METHOD_POST, $url);
                    $request->setContent(http_build_query($params = array(
                        'oauth_consumer_key'     => $clientId,
                        'oauth_nonce' => $nonce,
                        'oauth_signature_method' => 'hmac-sha1',
                        'oauth_timestamp'          => time(),
                        'oauth_token'   => $returnvalues['oauth_token'],
                        'oauth_verifier'    => $returnvalues['oauth_verifier'],
                        'oauth_version'    => '1.0',
                        'oauth_signature' => $sig,
                    )));


        $response = new Response();
        $this->client->send($request, $response);

        parse_str($response->getContent(),$output);

        //echo  $returnvalues['oauth_token'];
        //print_r($output);
        //exit;


        $userguid = $output['xoauth_yahoo_guid'];


        $data = json_decode($response->getContent());
        if (isset($data->error)) {
            return;
        }
        $expiresAt = time()+$output['oauth_expires_in'];

        $url = 'http://social.yahooapis.com/v1/user/' . $userguid . '/profile';
        $nonce = mt_rand();
        $q = 'select * from social.profile where guid=me';

        $params =     'oauth_consumer_key=' . $clientId
                    . '&oauth_nonce=' . $nonce
                    . '&oauth_signature_method=' . 'HMAC-SHA1'
                    . '&oauth_timestamp='. time()
                    . '&oauth_token=' .$output['oauth_token']
                    . '&oauth_version=' . '1.0';

        $signature_base = 'GET' . '&' . rawurlencode($url) . '&' . rawurlencode($params);
        $signature_key = rawurlencode($secret) . '&' . rawurlencode($this->session->get('yahoo.oauth_token_secret'));
        $sig = base64_encode(hash_hmac('sha1', $signature_base, $signature_key,true));

        $auth_header = 'Authorization: OAuth realm="yahooapis.com"'
                      . ',' . rawurlencode('oauth_consumer_key')      . '="'  .   rawurlencode($clientId)                       .   '"'
                      . ',' . rawurlencode('oauth_nonce')             . '="'  .   rawurlencode($nonce)                          .   '"'
                      . ',' . rawurlencode('oauth_signature_method')  . '="'  .   rawurlencode('HMAC-SHA1')                     .   '"'
                      . ',' . rawurlencode('oauth_timestamp')         . '="'  .   rawurlencode(time())                          .   '"'
                      . ',' . rawurlencode('oauth_token')             . '="'  .   rawurlencode($output['oauth_token'])          .   '"'
                      . ',' . rawurlencode('oauth_version')           . '="'  .   rawurlencode('1.0')                           .   '"'
                      . ',' . rawurlencode('oauth_signature')         . '="'  .   rawurlencode($sig)                            .   '"';


        $request = new Request(Request::METHOD_GET, $url);
        $request->setHeaders(array(
                                   // 'Content-Type' => "application/x-www-form-urlencoded",
                                    'Authorization'=>$auth_header,

        ));


        $response = new Response();

        //print_r($request);
        //exit;

        $this->client->send($request, $response);

        print_r($response);
        exit;

        $me = json_decode($response->getContent());

        return new YahooToken($me, $data->access_token, $expiresAt);
    }

    public function getAuthorizationUrl($clientId, $scope, $redirectUrl, $secret)
    {
        $url = 'https://api.login.yahoo.com/oauth/v2/get_request_token';

        $request = new Request(Request::METHOD_POST, $url);
                $request->setContent(http_build_query(array(
                    'oauth_callback'  => urldecode($redirectUrl),
                    'oauth_consumer_key'     => $clientId,
                    'oauth_nonce' => 434098098,
                    'oauth_signature' => $secret . '&',
                    'oauth_signature_method' => 'plaintext',
                    'oauth_timestamp'          => time(),
                    'oauth_version'    => '1.0',
                )));



        $response = new Response();
        $this->client->send($request, $response);
        $data = json_decode($response->getContent());

        parse_str($response->getContent(),$output);

        $this->session->set('yahoo.oauth_token_secret',$output['oauth_token_secret']);

        return 'https://api.login.yahoo.com/oauth/v2/request_auth'
            .'?oauth_token='.$output['oauth_token'];
    }

}