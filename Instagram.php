<?php

namespace evgenybalashov\authclient;

use yii\authclient\OAuthToken;

class Instagram extends InstagramOAuth2
{
    /**
     * @inheritdoc
     */
    public $authUrl = 'https://api.instagram.com/oauth/authorize';

    /**
     * @inheritdoc
     */
    public $tokenUrl = 'https://api.instagram.com/oauth/access_token';

    /**
     * @inheritdoc
     */
    public $apiBaseUrl = 'https://graph.instagram.com';

    /**
     * @var array list of attribute names, which should be requested from API to initialize user attributes.
     * @since 2.0.5
     */
    public $attributeNames = [
        'id',
        'username',
    ];

    /**
     * @inheritdoc
     */
    protected function initUserAttributes()
    {
        return $this->api('me', 'GET', [
            'fields' => implode(',', $this->attributeNames),
        ]);
    }

    /**
     * @inheritdoc
     */
    protected function apiInternal($accessToken, $url, $method, array $params, array $headers)
    {
        return $this->sendRequest($method, $url . '?access_token=' . $accessToken->getToken(), $params, $headers);
    }

    /**
     * @inheritdoc
     */
    protected function defaultName()
    {
        return 'instagram';
    }

    /**
     * @inheritdoc
     */
    protected function defaultTitle()
    {
        return 'Instagram';
    }


    /**
     * {@inheritdoc}
     */
    public function fetchAccessToken($authCode, array $params = [])
    {
        $token = parent::fetchAccessToken($authCode, $params);
        return $token;
    }

    /**
     * Exchanges short-live (2 hours) access token to long-live (60 days) one.
     * Note that this method will success for already long-live token, but will not actually prolong it any further.
     * Pay attention, that this method will fail on already expired access token.
     * @see https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     * @param OAuthToken $token short-live access token.
     * @return OAuthToken long-live access token.
     * @since 2.1.3
     */
    public function exchangeAccessToken(OAuthToken $token)
    {
        $params = [
            'grant_type' => 'fb_exchange_token',
            'fb_exchange_token' => $token->getToken(),
        ];

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->tokenUrl)
            ->setData($params);

        $this->applyClientCredentialsToRequest($request);

        $response = $this->sendRequest($request);

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }

    /**
     * Requests the authorization code for the client-specific access token.
     * This make sense for the distributed applications, which provides several Auth clients (web and mobile)
     * to avoid triggering Facebook's automated spam systems.
     * @see https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     * @see fetchClientAccessToken()
     * @param OAuthToken|null $token access token, if not set [[accessToken]] will be used.
     * @param array $params additional request params.
     * @return string client auth code.
     * @since 2.1.3
     */
    public function fetchClientAuthCode(OAuthToken $token = null, $params = [])
    {
        if ($token === null) {
            $token = $this->getAccessToken();
        }

        $params = array_merge([
            'access_token' => $token->getToken(),
            'redirect_uri' => $this->getReturnUrl(),
        ], $params);

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->clientAuthCodeUrl)
            ->setData($params);

        $this->applyClientCredentialsToRequest($request);

        $response = $this->sendRequest($request);

        return $response['code'];
    }

    /**
     * Fetches access token from client-specific authorization code.
     * This make sense for the distributed applications, which provides several Auth clients (web and mobile)
     * to avoid triggering Facebook's automated spam systems.
     * @see https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
     * @see fetchClientAuthCode()
     * @param string $authCode client auth code.
     * @param array $params
     * @return OAuthToken long-live client-specific access token.
     * @since 2.1.3
     */
    public function fetchClientAccessToken($authCode, array $params = [])
    {
        $params = array_merge([
            'code' => $authCode,
            'redirect_uri' => $this->getReturnUrl(),
            'client_id' => $this->clientId,
        ], $params);

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->tokenUrl)
            ->setData($params);

        $response = $this->sendRequest($request);

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }
}
