<?php
    declare(strict_types=1);

    namespace LourensSystems\ApiWrapper\Endpoints;

    use GuzzleHttp\Client;
    use GuzzleHttp\Exception\ClientException;
    use LourensSystems\ApiWrapper\Endpoints\Parameters\GetParameters;
    use LourensSystems\ApiWrapper\Endpoints\Parameters\PdfParameters;
    use LourensSystems\ApiWrapper\Endpoints\Parameters\PreviewParameters;
    use LourensSystems\ApiWrapper\Exception\Feature\FeatureHardLimitException;
    use LourensSystems\ApiWrapper\Exception\Feature\FeatureLimitException;
    use LourensSystems\ApiWrapper\Exception\Feature\FeatureSoftLimitException;
    use LourensSystems\ApiWrapper\Exception\Feature\FeatureTotalLimitException;
    use LourensSystems\ApiWrapper\OAuth2\Client\Provider\Provider;
    use Psr\Http\Message\RequestInterface;
    use LourensSystems\ApiWrapper\Response\Response;
    use LourensSystems\ApiWrapper\Endpoints\Parameters\ListParameters;
    use LourensSystems\ApiWrapper\Exception\BadRequestException;
    use LourensSystems\ApiWrapper\Exception\RateLimitException;
    use Zend\Diactoros\Stream;
    use League\OAuth2\Client\Token\AccessToken;
    use Psr\Http\Message\ResponseInterface;
    use LourensSystems\ApiWrapper\Exception\AuthException;
    use LourensSystems\ApiWrapper\Exception\MethodNotAllowedException;
    use LourensSystems\ApiWrapper\Exception\NotFoundException;
    use LourensSystems\ApiWrapper\Exception\NoFeatureException;
    use LourensSystems\ApiWrapper\Exception\NoPermissionsException;
    use LourensSystems\ApiWrapper\Exception\ServerException;
    use LourensSystems\ApiWrapper\Exception\ValidationFailedException;
    use LourensSystems\ApiWrapper\Exception\EntityTooLargeException;

    /**
     * Class AbstractEndpoint
     * @package LourensSystems\ApiWrapper\Endpoints
     */
    abstract class AbstractEndpoint
    {

        const METHOD_GET = 'GET';
        const METHOD_POST = 'POST';
        const METHOD_PUT = 'PUT';
        const METHOD_DELETE = 'DELETE';
        const METHOD_PATCH = 'PATCH';


        /**
         * @var Provider
         */
        protected $provider;

        /**
         * @var Client;
         */
        protected $httpClient;

        /**
         * @var string
         */
        protected $baseUrl;

        /**
         * @var
         */
        protected $refreshToken;

        /**
         * @var AccessToken
         */
        protected $accessToken;

        /**
         * @var array
         */
        protected $scopes = [];

        /**
         * @var string
         */
        protected $language;

        /**
         * AbstractEndpoint constructor.
         * @param Provider $provider
         * @param string|null $refreshToken
         */
        public function __construct(Provider $provider, string $refreshToken = null)
        {
            $this->setProvider($provider);

            if ($refreshToken !== null) {
                $this->setRefreshToken($refreshToken);
            }

            $this->setBaseUrl($this->provider->getBaseUrl());
            $this->checkBaseUrl();

            $this->httpClient = $this->provider->getHttpClient();
        }

        /**
         * @param string $refreshToken
         */
        public function setRefreshToken(string $refreshToken)
        {
            $this->refreshToken = $refreshToken;
            $this->accessToken = null;
        }

        /**
         * @param Provider $provider
         */
        public function setProvider(Provider $provider)
        {
            $this->provider = $provider;
        }

        /**
         * @param string $baseUrl
         */
        public function setBaseUrl(string $baseUrl)
        {
            $this->baseUrl = $baseUrl;
        }

        /**
         * @param AccessToken $accessToken
         */
        public function setAccessToken(AccessToken $accessToken)
        {
            $this->accessToken = $accessToken;
        }

        /**
         * Setter for custom scopes, normally scopes come from the endpoint class
         * @param array $scopes
         */
        public function setScopes(array $scopes)
        {
            $this->scopes = $scopes;
        }

        /**
         * Setting request language. Necessary for endpoints that return translateable content.
         *
         * @param string $language
         */
        public function setLanguage(string $language)
        {
            $this->language = $language;
        }

        /**
         * @return AccessToken
         */
        public function getAccessToken(): AccessToken
        {
            $this->checkAccessToken();

            return $this->accessToken;
        }

        /**
         * @return Provider
         */
        public function getProvider(): Provider
        {
            return $this->provider;
        }

        /**
         * @throws \Exception
         */
        protected function checkBaseUrl()
        {
            if (!preg_match('/^(http|https):\\/\\/[a-z0-9_]+([\\-\\.]{1}[a-z_0-9]+)*\\.[_a-z]{2,5}' . '((:[0-9]{1,5})?\\/.*)?$/i',
                $this->baseUrl)
            ) {
                throw new \Exception('Logic exception: invalid baseUrl set.');
            }
        }

        /**
         * Checks if access token is not set or expired, fetches new one if needed.
         */
        protected function checkAccessToken()
        {
            if (!isset($this->accessToken) || $this->accessToken->hasExpired()) {
                if ($this->refreshToken) {
                    $this->accessToken = $this->provider->getAccessToken('refresh_token', [
                        'refresh_token' => $this->refreshToken,
                        'scope'         => implode(' ', $this->scopes)
                    ]);
                } else {
                    $this->accessToken = $this->provider->getAccessToken('client_credentials',
                        ['scope' => implode(' ', $this->scopes)]);
                }
            }
        }

        /**
         * @param string $method One of self::METHOD_XXX constants.
         * @param string $url
         * @param array $data
         * @return Response
         */
        protected function callApi(string $method, string $url, array $data = []): Response
        {
            $this->checkAccessToken();

            try {
                $request = $this->getRequest($method, $url);
                $options = $this->prepareApiOptions($data);

                return Response::createFromResponse($this->httpClient->send($request, $options));
            } catch (ClientException $e) {
                $this->processResponse($e->getRequest(), $e->getResponse());
            } catch (\GuzzleHttp\Exception\ServerException $e) {
                $this->processResponse($e->getRequest(), $e->getResponse());
            }
        }

        /**
         * Preparing request object.
         *
         * @param string $method
         * @param string $url
         * @return RequestInterface
         */
        protected function getRequest(string $method, string $url): RequestInterface
        {
            $request = $this->provider->getAuthenticatedRequest($method, $url, $this->accessToken);

            if (isset($this->language)) {
                $request = $request->withHeader('Accept-Language', $this->language);
            }

            return $request;
        }

        /**
         * @param array $data
         * @return array
         */
        protected function prepareApiOptions(array $data = [])
        {
            if (isset($data['file']) && $data['file'] !== null && !empty($data['file'])) {
                $options = $this->prepareRequestFileOptions($data);
            } else {
                $options = $this->prepareRequestOptions($data);
            }

            return $options;
        }

        /**
         * Prepares options for standard request
         * @param array $data
         * @return array
         */
        protected function prepareRequestOptions(array $data)
        {
            $options = [];
            if ($data !== null) {
                $stream = new Stream('php://temp', 'r+');
                $stream->write(\GuzzleHttp\json_encode($data, JSON_PRESERVE_ZERO_FRACTION));

                $options['body'] = $stream;
                $options['headers'] = ['Content-Type' => 'application/json'];
            }

            return $options;
        }


        /**
         * Prepares request options for sending/uploading files
         * @param array $data
         * @return array
         */
        protected function prepareRequestFileOptions(array $data)
        {
            $fileExists = file_exists($data['file']['filePath']);

            $options = [
                'multipart' => [
                    [
                        'name'     => 'file',
                        'contents' => $fileExists ? fopen($data['file']['filePath'], 'r') : '',
                        'filename' => $fileExists ? $data['file']['originalName'] : '',
                        'headers'  => [
                            'Content-Type' => $fileExists ? (new \finfo(FILEINFO_MIME))->file($data['file']['filePath']) : ''
                        ]
                    ]
                ]
            ];
            //add additional data if needed
            if ($data['data'] !== null) {
                $options['multipart'][] = [
                    'name'     => 'data',
                    'contents' => \GuzzleHttp\json_encode($data['data'], JSON_PRESERVE_ZERO_FRACTION)
                ];
            }

            return $options;
        }

        /**
         * @param RequestInterface $request
         * @param ResponseInterface $response
         * @throws AuthException
         * @throws BadRequestException
         * @throws MethodNotAllowedException
         * @throws NotFoundException
         * @throws NoPermissionsException
         * @throws ServerException
         * @throws RateLimitException
         * @throws ValidationFailedException
         */
        protected function processResponse(RequestInterface $request, ResponseInterface $response)
        {
            $body = json_decode((string)$response->getBody(), true);

            switch ($response->getStatusCode()) {
                case 400:
                    $exception = BadRequestException::createNewWithRequestResponse($request, $response);
                    break;
                case 401:
                    $exception = AuthException::createNewWithRequestResponse($request, $response);
                    $exception->setErrorType($body['meta']['error_type']);
                    $exception->setHint($body['meta']['hint']);
                    break;
                case 402:
                    switch ($body['code']) {
                        case 4001:
                            $exception = FeatureHardLimitException::createNewWithRequestResponse($request, $response);
                            break;
                        case 4002:
                            $exception = FeatureSoftLimitException::createNewWithRequestResponse($request, $response);
                            break;
                        case 4003:
                            $exception = FeatureTotalLimitException::createNewWithRequestResponse($request, $response);
                            break;
                        default:
                            $exception = FeatureLimitException::createNewWithRequestResponse($request, $response);
                    }
                    $exception->setLimit($body['meta']['limit']);
                    $exception->setFeature($body['meta']['feature']);
                    break;
                case 403:
                    if (isset($body['meta']['feature'])) {
                        $exception = NoFeatureException::createNewWithRequestResponse($request, $response);
                        $exception->setFeature($body['meta']['feature']);
                        $exception->setPlans($body['meta']['plans']);
                    } else {
                        $exception = NoPermissionsException::createNewWithRequestResponse($request, $response);
                    }
                    break;
                case 404:
                    $exception = NotFoundException::createNewWithRequestResponse($request, $response);
                    $exception->setEntityType($body['meta']['entity_type']);
                    break;
                case 405:
                    $exception = MethodNotAllowedException::createNewWithRequestResponse($request, $response);
                    break;
                case 413:
                    $exception = EntityTooLargeException::createNewWithRequestResponse($request, $response);
                    break;
                case 422:
                    $exception = ValidationFailedException::createNewWithRequestResponse($request, $response);
                    $exception->setErrorsData($body['meta']['errors']);
                    break;
                case 429:
                    $exception = RateLimitException::createNewWithRequestResponse($request, $response);
                    break;
                case 500:
                default:
                    $exception = ServerException::createNewWithRequestResponse($request, $response);
            }

            throw $exception;
        }

        /**
         * Prepares url.
         * @param string $endpointUrl
         * @param ListParameters|null $parameters
         * @return string
         */
        protected function prepareListUrl(string $endpointUrl, ListParameters $parameters = null): string
        {
            $params = [];
            if (!is_null($parameters)) {
                if ($parameters->hasQ()) {
                    $params[] = 'q=' . $parameters->getQ();
                }
                if ($parameters->hasFilter()) {
                    $params[] = 'filter=' . urlencode($parameters->getFilter());
                }
                if ($parameters->hasWidth()) {
                    $params[] = 'with=' . $parameters->getWith();
                }
                if ($parameters->hasLimit()) {
                    $params[] = 'limit=' . $parameters->getLimit();
                }
                if ($parameters->hasOffset()) {
                    $params[] = 'offset=' . $parameters->getOffset();
                }
                if ($parameters->hasSort()) {
                    $params[] = 'sort=' . $parameters->getSort();
                }
            }

            if (!empty($params)) {
                $endpointUrl .= '?' . implode('&', $params);
            }

            return $this->baseUrl . $endpointUrl;
        }

        /**
         * @param string $endpointUrl
         * @param GetParameters|null $parameters
         * @return string
         */
        protected function prepareGetUrl(string $endpointUrl, GetParameters $parameters = null): string
        {
            $params = [];
            if (!is_null($parameters)) {
                if ($parameters->hasWidth()) {
                    $params[] = 'with=' . $parameters->getWith();
                }
            }

            if (!empty($params)) {
                $endpointUrl .= '?' . implode('&', $params);
            }

            return $this->baseUrl . $endpointUrl;
        }

        /**
         * Prepares URL for pdf action
         * @param string $endpointUrl
         * @param PdfParameters|null $parameters
         * @return string
         */
        protected function preparePdfUrl(string $endpointUrl, PdfParameters $parameters = null): string
        {
            $params = [];
            if (!is_null($parameters)) {
                if ($parameters->hasOptions()) {
                    $params[] = 'options=' . $parameters->getOptions();
                }
            }

            if (!empty($params)) {
                $endpointUrl .= '?' . implode('&', $params);
            }

            return $this->baseUrl . $endpointUrl;
        }

        /**
         * Prepares URL for preview action
         * @param string $endpointUrl
         * @param PreviewParameters|null $parameters
         * @return string
         */
        protected function preparePreviewUrl(string $endpointUrl, PreviewParameters $parameters = null): string
        {
            $params = [];
            if (!is_null($parameters)) {
                if ($parameters->hasSize()) {
                    $params[] = 'size=' . $parameters->getSize();
                }

                if ($parameters->hasPage()) {
                    $params[] = 'page=' . $parameters->getPage();
                }
            }

            if (!empty($params)) {
                $endpointUrl .= '?' . implode('&', $params);
            }

            return $this->baseUrl . $endpointUrl;
        }
    }