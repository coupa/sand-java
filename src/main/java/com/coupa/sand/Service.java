package com.coupa.sand;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import net.minidev.json.JSONObject;
import org.apache.http.*;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 *  This class creates a Service for checking if a request has access,
 *  by verifying the token with the SAND server.
 *
 * @author Mattias Kjetselberg
 */
public class Service extends Client {
    private static final Logger LOGGER = LoggerFactory.getLogger(Service.class);
    private static final String DEFAULT_TOKEN_VERIFY_PATH = "/warden/token/allowed";
    private static final String[] DEFAULT_ACCESS_SCOPES = new String[] {"hydra"};
    private static final String DEFAULT_SERVICE_CACHE_TYPE = "tokens";
    private static final Map<String, Object> DEFAULT_CONTEXT = Collections.EMPTY_MAP;
    private static final String SERVICE_CACHING_KEY = "service-access-token";
    private static final String TOKEN_VERIFICATION_FIELD_SCOPES = "scopes";
    private static final String TOKEN_VERIFICATION_FIELD_TOKEN = "token";
    private static final String TOKEN_VERIFICATION_FIELD_RESOURCE = "resource";
    private static final String TOKEN_VERIFICATION_FIELD_ACTION = "action";
    private static final String TOKEN_VERIFICATION_FIELD_CONTEXT = "context";

    Client iClient = null;
    String iResource = null;
    Map<String, Object> iContext = DEFAULT_CONTEXT;
    String iTokenVerifyPath = DEFAULT_TOKEN_VERIFY_PATH;
    String[] iScopes = DEFAULT_ACCESS_SCOPES;

    /**
     * Cache to avoid repeated calls to SAND server.
     * Tokens responses are cached for 1 hour.
     */
    private static final Cache<String, AllowedResponse> cTokenResponseCache =
            CacheBuilder
                    .newBuilder()
                    .concurrencyLevel(4)
                    .maximumSize(1000)
                    .expireAfterWrite(1L, TimeUnit.HOURS)
                    .build();

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
    public Service(String clientId, String secret, String tokenSite, String resource) {
        this(clientId, secret, tokenSite, DEFAULT_TOKEN_PATH, resource, DEFAULT_TOKEN_VERIFY_PATH);
    }

    /**
     * Constructor that will set default values for
     * scopes = {"hydra"}
     * cacheType = "tokens"
     *
     * @param clientId The ID of the Client that's registered in the SAND server.
     * @param secret The Secret of the Client that's registred in the SAND server.
     * @param tokenSite The URL to the SAND server.
     * @param tokenPath The endpoint on the SAND server to request an oauth token.
     * @param resource The Resource that this Service will verify tokens against.
     * @param tokenVerifyPath The URI on the SAND server for verifying a token.
     */
    public Service(String clientId, String secret, String tokenSite, String tokenPath, String resource, String tokenVerifyPath) {
        this(clientId, secret, tokenSite, tokenPath, resource, tokenVerifyPath, DEFAULT_ACCESS_SCOPES);
    }

    /**
     * Constructor that will set default value for
     * cacheType = "tokens"
     *
     * @param clientId The ID of the Client that's registered in the SAND server.
     * @param secret The Secret of the Client that's registred in the SAND server.
     * @param tokenSite The URL to the SAND server.
     * @param tokenPath The URI on the SAND server to request an oauth token.
     * @param resource The Resource that this Service will verify tokens against.
     * @param tokenVerifyPath The URI on the SAND server for verifying a token.
     * @param scopes The scopes for fetching an authentication token to use for verifying a token.
     */
    public Service(String clientId, String secret, String tokenSite, String tokenPath, String resource, String tokenVerifyPath, String[] scopes) {
        iClient = new Client(clientId, secret, tokenSite, tokenPath);
        iResource = resource;
        iTokenVerifyPath = tokenVerifyPath;
        iScopes = scopes;
        iCacheType = DEFAULT_SERVICE_CACHE_TYPE;
    }

    /**
     * Checks if the request is authorized by verifying the token in the request
     * with targetScopes and action, and adding the default retry count.
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
                                        String action) throws AuthenticationException {

        return checkRequest(request, targetScopes, action, DEFAULT_RETRY_COUNT);
    }

    /**
     * Checks if the request is authorized by verifying the token in the request with the rest of the parameters.
     * Examples in the checkRequest function above, this function has the added possibility to configure numRetries.
     *
     * @param request The request to check if it's authorized.
     * @param targetScopes The scopes to verify the request against.
     * @param action The action to verify the request against.
     * @param numRetries Number of times the service should retry to get an access token for verification.
     *
     * @return AllowedResponse if the token should be allowed access, gotten from the function isAllowed();
     *
     * @throws AuthenticationException if the Service should should return errorStatusCode()
     * to the requesting Client so that the Client will not retry.
     */
    public AllowedResponse checkRequest(HttpRequest request,
                                        String[] targetScopes,
                                        String action,
                                        int numRetries) throws  AuthenticationException {

        String token = extractToken(request);

        if (token == null || token.isEmpty()) {
            throw new AuthenticationException("Failed to extract the token from the request");
        }

        VerificationOptions options = new VerificationOptions(targetScopes, action, iResource, numRetries);

        return checkToken(token, options);

    }

    /**
     * Extracts a token from an apache.org.http request, by checking the Authoriation header.
     * Header value must be of format "Bearer #{token}"
     *
     * @param request The request to fetch the token from.
     *
     * @return String The token from the request authorization header.
     */
    private String extractToken(HttpRequest request) {
        Header authHeader = request.getFirstHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null) {
            String[] headerValues = authHeader.getValue().split(" ");

            if ("bearer".equalsIgnoreCase(headerValues[0])) {
                return headerValues[1];
            }
        }

        return null;
    }

    /**
     * Checks if the token should be allowed access, first by checking if there is a cached verification response
     * for the token, otherwise requesting the SAND server to verify the token.
     * If the token is verified by the SAND server, the response will be cached for future checks.
     *
     * @param token The token to verify
     * @param options The options to verify the token against. (scopes, action, context)
     *
     * @return AllowedResponse if the token should be allowed access, gotten from the function isAllowed();
     *
     * @throws AuthenticationException if the Service should should return errorStatusCode()
     * to the requesting Client so that the Client will not retry.
     */
    private AllowedResponse checkToken(String token, VerificationOptions options) throws AuthenticationException {
        String cachingKey = cacheKey(token, options.getTargetScopes(), options.getResource(), options.getAction());
        AllowedResponse cachedAllowedResponse = getTokenResponseFromCache(token);

        if (cachedAllowedResponse != null) {
            return  cachedAllowedResponse;
        }

        AllowedResponse verifyTokenResponse = verifyToken(token, options);

        if (verifyTokenResponse == null) {
            return new AllowedResponse(false);
        }
        else {
            cacheTokenResponse(token, verifyTokenResponse);
        }

        return verifyTokenResponse;
    }

    /**
     * Verifies a token with the SAND server.
     *
     * @param token The token to verify
     * @param options The options to verify the token against. (scopes, action, context)
     *
     * @return AllowedResponse if the token should be allowed access, gotten from the function isAllowed();
     *
     * @throws AuthenticationException if the Service should should return errorStatusCode()
     * to the requesting Client so that the Client will not retry.
     */
    private AllowedResponse verifyToken(String token, VerificationOptions options) throws AuthenticationException {
        String accessToken = getAccessToken(options.getNumRetries());

        if (accessToken == null || accessToken.isEmpty()) {
            throw new AuthenticationException("Could not get a service access token");
        }

        HttpPost httpPost = createTokenVerificationRequest(token, options, accessToken);

        return sendTokenVerificationRequest(httpPost);
    }

    /**
     * Sends a token verification request to the SAND server.
     *
     * @param httpPost The token verification request.
     *
     * @return AllowedResponse if the token should be allowed access, gotten from the function isAllowed();
     *
     * @throws AuthenticationException if the Service should should return errorStatusCode()
     * to the requesting Client so that the Client will not retry.
     */
    private AllowedResponse sendTokenVerificationRequest(HttpPost httpPost) throws AuthenticationException {
        try (CloseableHttpClient client = httpClientWithPlanner()) {
            CloseableHttpResponse response = client.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity responseEntity = response.getEntity();
            Map<String, Object> jsonResponse = new Gson().fromJson(new InputStreamReader(responseEntity.getContent()), Map.class);

            if (statusCode == HttpStatus.SC_OK) {
                return new AllowedResponse(jsonResponse);
            }
            else if (statusCode != HttpStatus.SC_INTERNAL_SERVER_ERROR) {
                throw new AuthenticationException(jsonResponse.toString());
            }
        } catch (IOException e) {
            LOGGER.error("Could not send a verification request", e);
            throw new AuthenticationException("Could not send a verification request");
        }

        return null;
    }

    /**
     * Get a closable Http client with planner, to use for making requests.
     *
     * @return a CloseableHttpClient.
     */
    private static CloseableHttpClient httpClientWithPlanner() {
        return HttpClients.custom().useSystemProperties().build();
    }

    /**
     * Creates a token verification request for the SAND server;
     *
     * @param token The token to verify
     * @param options The options to verify the token against. (scopes, action, resource, context)
     * @param accessToken The token to use for access to the SAND server verification endpoint.
     *
     * @return HttpPost request
     */
    private HttpPost createTokenVerificationRequest(String token,
                                                    VerificationOptions options,
                                                    String accessToken) {

        HttpPost httpPost = new HttpPost(iClient.getTokenSite() + iTokenVerifyPath);
        httpPost.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        httpPost.setHeader(HttpHeaders.ACCEPT, "application/json");
        httpPost.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");

        JSONObject jsonPostParams = new JSONObject();
        jsonPostParams.appendField(TOKEN_VERIFICATION_FIELD_SCOPES, options.getTargetScopes());
        jsonPostParams.appendField(TOKEN_VERIFICATION_FIELD_TOKEN, token);
        jsonPostParams.appendField(TOKEN_VERIFICATION_FIELD_RESOURCE, options.getResource());
        jsonPostParams.appendField(TOKEN_VERIFICATION_FIELD_ACTION, options.getAction());
        jsonPostParams.appendField(TOKEN_VERIFICATION_FIELD_CONTEXT, options.getContext());

        HttpEntity postParams = new StringEntity(jsonPostParams.toString(), StandardCharsets.UTF_8);
        httpPost.setEntity(postParams);

        return httpPost;
    }

    /**
     * Get an access token for the SAND server token verification endpoint.
     * Cache will be used to reduce requests to the SAND server.
     *
     * @param numRetries Number of retries to fetch the access token from the SAND server.
     *
     * @return String the access token.
     */
    private String getAccessToken(int numRetries) {
        String cachingKey = cacheKey(SERVICE_CACHING_KEY, iScopes, null, null);

        return iClient.getToken(cachingKey, iScopes, numRetries);
    }

    /**
     * Fetches the token verification response from the cache
     * and returns it if it hasn't expired.
     *
     * @param cachingKey The key to look for in the cache.
     *
     * @return AllowedResponse from the cache.
     */
    private AllowedResponse getTokenResponseFromCache(String cachingKey) {
        if (cachingKey != null) {
            AllowedResponse cachedResponse = cTokenResponseCache.getIfPresent(cachingKey);

            if (isExpired(cachedResponse)) {
                removeCachedTokenResponse(cachingKey);
            }
            else {
                return cachedResponse;
            }
        }

        return null;
    }

    /**
     * Checks if the response expiry time has passsed.
     * If the response doesn't have an expiry time, it's considered not expired.
     *
     * @param allowedResponse The token verification response.
     *
     * @return boolean if the response has expired.
     */
    private boolean isExpired(AllowedResponse allowedResponse) {
        if (allowedResponse != null) {
            String expires = allowedResponse.getExp();

            if (expires != null) {
                OffsetDateTime timeExpires = OffsetDateTime.parse(expires);
                OffsetDateTime timeNow = OffsetDateTime.now(timeExpires.getOffset());

                return timeNow.isAfter(timeExpires);
            }

            return false;
        }

        return true;
    }

    /**
     * Caching a token response.
     *
     * @param cachingKey The key to use for the caching.
     * @param allowedResponse The response to cache.
     */
    private void cacheTokenResponse(String cachingKey, AllowedResponse allowedResponse) {
        if (cachingKey != null) {
            cTokenResponseCache.put(cachingKey, allowedResponse);
        }
    }

    /**
     * Removing a cached token response.
     *
     * @param cachingKey The key to remove from the cache.
     */
    private void removeCachedTokenResponse(String cachingKey) {
        if (cachingKey != null) {
            cTokenResponseCache.invalidate(cachingKey);
        }
    }

    // class for setting options a token should be verified against.
    class VerificationOptions {
        String[] iTargetScopes;
        String iAction;
        String iResource;
        Map<String, String> iContext = new HashMap<>();
        int iNumRetries;

        /**
         * Constructor that will throw an AuthenticationException
         * if the resource parameter is empty.
         *
         * @param targetScopes The scopes to verify the token against.
         * @param action The action to verify the token against.
         * @param resource The resource to verify the token against.
         * @param numRetries Number of retries to get an access token for the verification.
         */
        public VerificationOptions(String[] targetScopes,
                                   String action,
                                   String resource,
                                   int numRetries) throws AuthenticationException {

            if (resource == null || resource.isEmpty()) {
                throw new AuthenticationException("This Service has no configured resource");
            }

            iTargetScopes = targetScopes;
            iResource = resource;
            iAction = action;
            iNumRetries = numRetries;
        }

        public String[] getTargetScopes() {
            return iTargetScopes;
        }

        public void setTargetScopes(String[] targetScopes) {
            iTargetScopes = targetScopes;
        }

        public String getResource() {
            return iResource;
        }

        public void setResource(String resource) {
            iResource = resource;
        }

        public String getAction() {
            return iAction;
        }

        public void setAction(String action) {
            iAction = action;
        }

        public Map<String, String> getContext() {
            return iContext;
        }

        public void setContext(Map<String, String> context) {
            iContext = context;
        }

        public int getNumRetries() {
            return iNumRetries;
        }

        public void setNumRetries(int numRetries) {
            iNumRetries = numRetries;
        }
    }
}
