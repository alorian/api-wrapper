<?php
    declare(strict_types=1);

    namespace LourensSystems\ApiWrapper\OAuth2\Client\Provider;

    use GuzzleHttp\Exception\ClientException;
    use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
    use League\OAuth2\Client\Token\AccessToken;
    use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
    use Psr\Http\Message\RequestInterface;
    use Psr\Http\Message\ResponseInterface;

    /**
     * Class Provider
     * @package LourensSystems\ApiWrapper\OAuth2\Client\Provider
     */
    class Provider extends \League\OAuth2\Client\Provider\AbstractProvider
    {

        use BearerAuthorizationTrait;

        /**
         * @var string
         */
        protected $baseUrl;

        /**
         * @var string
         */
        protected $urlAuthorize;

        /**
         * @var string
         */
        protected $urlAccessToken;

        /**
         * @var string
         */
        protected $urlResourceOwnerDetails;

        /**
         * Sets base API URL.
         * @param string $baseUrl
         */
        public function setBaseUrl(string $baseUrl)
        {
            $this->baseUrl = $baseUrl;
        }

        /**
         * Gets base API URL
         * @return string
         */
        public function getBaseUrl(): string
        {
            return $this->baseUrl;
        }

        /**
         * @inheritdoc
         */
        public function getBaseAuthorizationUrl()
        {
            return isset($this->urlAuthorize) ? $this->urlAuthorize : $this->getBaseUrl() . '/auth/authorize';
        }

        /**
         * @inheritdoc
         */
        public function getBaseAccessTokenUrl(array $params)
        {
            return isset($this->urlAccessToken) ? $this->urlAccessToken : $this->getBaseUrl() . '/auth/access-tokens';
        }

        /**
         * @inheritdoc
         */
        public function getResourceOwnerDetailsUrl(AccessToken $token)
        {
            return isset($this->urlResourceOwnerDetails) ? $this->urlResourceOwnerDetails : $this->getBaseUrl() . '/auth/owner';
        }

        /**
         * @inheritdoc
         */
        protected function createResourceOwner(array $response, AccessToken $token)
        {
            return new ResourceOwner($response);
        }

        /**
         * @inheritdoc
         */
        protected function getDefaultScopes()
        {
            return [];
        }

        /**
         * @inheritdoc
         */
        public function getResponse(RequestInterface $request)
        {
            try {
                $response = $this->getHttpClient()->send($request);
            } catch (BadResponseException $e) {
                $response = $e->getResponse();
            }
            
            try {
                $parsed = $this->parseResponse($response);
                $this->checkResponse($response, $parsed);
            } catch (IdentityProviderException $e) {
                throw new ClientException($e->getMessage(), $request, $response);
            } catch (\UnexpectedValueException $e) {
                throw new ClientException($e->getMessage(), $request, $response);
            }

            return $response;
        }

        /**
         * @inheritdoc
         */
        protected function checkResponse(ResponseInterface $response, $data)
        {
            if ($response->getStatusCode() != 200 && $response->getStatusCode() != 201) {
                throw new IdentityProviderException(
                    isset($data['error']) ? $data['error'] : $response->getReasonPhrase(),
                    $response->getStatusCode(),
                    $response
                );
            }
        }
    }
