# sand-java
Java library for service authentication via OAuth2

A client who wants to communicate with a service, it will request a token from the OAuth2 server and use this token to make an API call to the service.

When a service receives a request with an OAuth bearer token, it verifies the token with the OAuth2 server to see if the token is allowed to access this service. The service acts like an OAuth2 Resource Server that verifies the token.

## Features

* The authentication is performed using the "client credentials" grant type in OAuth2.
* The tokens will be cached on both the client and the service sides.

## Instruction


A client that intends to communicate with a service can use Client to send the request. Client.request(...) will fetch token for SAND authentication and perform retries and caching.
```
    /**
     * Constructor tokenPath can be omitted to use the default "/oauth2/token"
     *
     * @param clientId The ID of the Client that's registered in the SAND server.
     * @param secret The Secret of the Client that's registred in the SAND server.
     * @param tokenSite The URL to the SAND server.
     * @param tokenPath The endpoint on the SAND server to request an oauth token.
     */
    public Client(String clientId, String clientSecret, String tokenSite, String tokenPath)



    /**
     * Makes a Client request to a Service by applying a token to the requestFunction parameter.
     * Will fetch new tokens and perform retries (at least one) if the response is 401.
     *
     * @param keyForCaching Key that will be used to build a caching key for storing request tokens.
     * @param scopes The scopes that the token will be created for.
     * @param retries Number of retries that will be done trying to fetch a token and to make the request.
     * @param requestFunction A function that will take a String token, make a request and return a HttpResponse.
     *                        Example:
     *                        public static HttpResponse requestWithToken(String token) {
     *                          //  Create a request to a Service
     *                          //  with "Bearer #{token}" in the Authorization header
     *                          //  execute the request and return the response.
     *
     *                          return HttpResponse;
     *                        }
     *
     * @return HttpResponse from the requested Service
     */
    public HttpResponse request(String keyForCaching,
                                String[] scopes,
                                int retries,
                                Function<String, HttpResponse> requestFunction)
```

A service that receives a request with the OAuth2 bearer token can use Service to verify the token with the OAuth2 server.

```
    /**
     * Constructor that will set default values for
     * tokenPath = "/oauth2/token"
     * tokenVerifyPath = "/warden/token/allowed"
     * scopes = {"hydra"}
     * cacheType = "tokens"
     *
     * @param clientId The ID of the Client that's registered in the SAND server.
     * @param secret The Secret of the Client that's registred in the SAND server.
     * @param tokenSite The URL to the SAND server.
     * @param resource The Resource that this Service will verify tokens against.
     */
    public Service(String clientId, String secret, String tokenSite, String resource)
    
    
    
    /**
    * Checks if the request is authorized by verifying the token in the request
    * with targetScopes and action.
    * numRetries can be omitted to use the default retry count.
    *
    * Example to verify a Client's request:
    * Service service = new Service(clientId, secret, tokenSite, resource);
    * String[] targetScopes = {"xxxxx"};
    * String action = "";
    *
    * try {
    *     AllowedResponse allowedResponse = service.checkRequest(request, targetScopes, action);
    *
    *     if (!allowedResponse.isAllowed()) {
    *         // set response code to accessDeniedStatusCode()    401
    *         // so the Client requesting will retry with a new token.
    *     }
    * } catch (AuthenticationException e) {
    *     // Set reponse code to errorStatusCode()     502
    *     // so the Client requesting will not make an unnecessary retry.
    * }
    *
    * @param request The request to check if it's authorized.
    * @param targetScopes The scopes to verify the request against.
    * @param action The action to verify the request against.
    * @param numRetries Number of times the service should retry to get an access token for verification.
    *
    * @return AllowedResponse if the token should be allowed access, gotten from the function isAllowed();
    * Allowed response will be created with information like:
    * {
    *      "sub":"client",
    *      "scopes":["myscope"],
    *      "iss":"hydra.localhost",
    *      "aud":"the-service",
    *      "iat":"2016-09-06T07:32:59.71-07:00",
    *      "exp":"2016-09-06T08:32:59.71-07:00",
    *      "ext":null,
    *      "allowed":true
    * }
    *
    * Not allowed response:
    * {
    *      "allowed":false
    * }
    *
    * @throws AuthenticationException if the Service should should return errorStatusCode()
    * to the requesting Client so that the Client will not retry.
    */
    public AllowedResponse checkRequest(HttpRequest request,
                                       String[] targetScopes,
                                       String action,
                                       int numRetries) throws AuthenticationException
```

### Client

`request` (primary use) function which can perform retry when encountering 401 responses from the service.

`getToken` function that first checks the cache for a token, then if necessary gets an OAuth token from authentication service.
Tokens will be cached up to one hour.

### Service

`CheckRequest` (primary use) function for verifying an HttpRequest with the authentication service on whether the client token in the request is allowed to communicate with this service.
The verification result will be cached for the token up to one hour.

`getAccessToken` function that will use the client's `getToken` function to receive a token for access to the token verification endpoint.