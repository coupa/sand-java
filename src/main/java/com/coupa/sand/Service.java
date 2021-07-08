package com.coupa.sand;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import net.minidev.json.JSONObject;
import org.apache.http.*;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.config.RequestConfig;
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
import java.util.Collections;
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
    private static final String[] DEFAULT_SERVICE_SCOPES = new String[] {"hydra"};
    private static final String DEFAULT_SERVICE_CACHE_TYPE = "tokens";
    private static final Map<String, Object> DEFAULT_CONTEXT = Collections.EMPTY_MAP;
    private static final String SERVICE_CACHING_KEY = "service-access-token";

    private static final String TOKEN_VERIFICATION_FIELD_SCOPES = "scopes";
    private static final String TOKEN_VERIFICATION_FIELD_TOKEN = "token";
    private static final String TOKEN_VERIFICATION_FIELD_RESOURCE = "resource";
    private static final String TOKEN_VERIFICATION_FIELD_ACTION = "action";
    private static final String TOKEN_VERIFICATION_FIELD_CONTEXT = "context";
    
    private static final int DEFAULT_HTTP_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_HTTP_SOCKET_TIMEOUT_MS = 5000;

    private static final int SERVICE_CACHE_DEFAULT_MAX_SIZE = 100000;
    private static final long SERVICE_CACHE_DEFAULT_EXPIRY_IN_SECS = 3599L;

    String iResource = null;
    Map<String, Object> iContext = DEFAULT_CONTEXT;
    String iTokenVerifyPath = DEFAULT_TOKEN_VERIFY_PATH;
    String[] iScopes = DEFAULT_SERVICE_SCOPES;

    /*
     * Secondary Token Cache
     */
    private static SecondaryCache<String, AllowedResponse> allowedResponseSecondaryCache;
    private static final String SECONDARY_CACHE_PROVIDER_NAME = "org.redisson.api.RedissonClient";
    
    static {
    	try {
    		Class.forName(SECONDARY_CACHE_PROVIDER_NAME, false, Client.class.getClassLoader());
    		allowedResponseSecondaryCache = new SecondaryCache<String, AllowedResponse>("sand-cache-authorizations");
    	} catch (ClassNotFoundException e) {
    		LOGGER.warn("Secondary Cache Provider {} Not Found", SECONDARY_CACHE_PROVIDER_NAME);
    	}
    }

    /**
     * Cache to avoid repeated calls to SAND server.
     * Tokens responses are cached for 1 hour.
     */
    private static Cache<String, AllowedResponse> cTokenResponseCache =
            CacheBuilder
                    .newBuilder()
                    .concurrencyLevel(4)
                    .maximumSize(SERVICE_CACHE_DEFAULT_MAX_SIZE)
                    .expireAfterWrite(SERVICE_CACHE_DEFAULT_EXPIRY_IN_SECS, TimeUnit.SECONDS)
                    .build();

    /**
     * This rebuilds the service cache of token responses with the specified expiry time and max size.
     * Use this method early at the beginning of your app to set custom expiry time and max size for the cache.
     * @param secs Cache expiry time in seconds. Default is 3599.
     * @param maxSize Maximum size of the cache. Default is 100000.
     */
    public static void buildServiceCacheWithExpiryAndSize(long secs, int maxSize) {
        if (maxSize < 1) {
            maxSize = SERVICE_CACHE_DEFAULT_MAX_SIZE;
        }
        if (secs < 1) {
            secs = SERVICE_CACHE_DEFAULT_EXPIRY_IN_SECS;
        }
        cTokenResponseCache = CacheBuilder
            .newBuilder()
            .concurrencyLevel(4)
            .maximumSize(maxSize)
            .expireAfterWrite(secs, TimeUnit.SECONDS)
            .build();
    }

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
        this(clientId, secret, tokenSite, tokenPath, resource, tokenVerifyPath, DEFAULT_SERVICE_SCOPES);
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
        super(clientId, secret, tokenSite, tokenPath);
        if (Util.hasEmpty(resource, tokenVerifyPath)) {
          throw new IllegalArgumentException("Service resource and token verification path are required");
        }
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

        if (Util.hasEmpty(token)) {
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
    public AllowedResponse checkToken(String token, VerificationOptions options) throws AuthenticationException {
        String cachingKey = cacheKey(token, options.getTargetScopes(), options.getResource(), options.getAction());
        AllowedResponse cachedAllowedResponse = getTokenResponseFromCache(cachingKey);

        if (cachedAllowedResponse != null) {
            return  cachedAllowedResponse;
        }

        AllowedResponse verifyTokenResponse = null;
        try {
            verifyTokenResponse = verifyToken(token, options);
        } catch (ServiceUnauthorizedException e) {
            LOGGER.error("Unauthorized to access token verification endpoint. Trying again");
            //Service received 401 when accessing the token verification endpoint, meaning the service token may
            //be invalid. So clear the service token cache and try once more.
            String key = this.cacheKey(SERVICE_CACHING_KEY, iScopes, null, null);
            removeCachedToken(key);
            
            try {
                verifyTokenResponse = verifyToken(token, options);
            } catch (ServiceUnauthorizedException e2) {
                throw new AuthenticationException("Service unable to authorize to the token verification endpoint");
            }
        }

        if (verifyTokenResponse == null) {
            return new AllowedResponse(false);
        }
        else {
            cacheTokenResponse(cachingKey, verifyTokenResponse);
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
    private AllowedResponse verifyToken(String token, VerificationOptions options) throws AuthenticationException, ServiceUnauthorizedException {
        String accessToken = getToken(SERVICE_CACHING_KEY, iScopes, options.getNumRetries());
        if (Util.hasEmpty(accessToken)) {
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
    private AllowedResponse sendTokenVerificationRequest(HttpPost httpPost) throws AuthenticationException, ServiceUnauthorizedException {
        try (CloseableHttpClient client = httpClientWithPlanner()) {
            CloseableHttpResponse response = client.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity responseEntity = response.getEntity();
            Map<String, Object> jsonResponse = new Gson().fromJson(new InputStreamReader(responseEntity.getContent()), Map.class);

            if (statusCode == HttpStatus.SC_OK) {
                return new AllowedResponse(jsonResponse);
            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                throw new ServiceUnauthorizedException();
            } else if (statusCode != HttpStatus.SC_INTERNAL_SERVER_ERROR) {
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
    	
    	RequestConfig requestConfig = RequestConfig.custom()
    		.setConnectTimeout(DEFAULT_HTTP_CONNECT_TIMEOUT_MS)
    		.setSocketTimeout(DEFAULT_HTTP_SOCKET_TIMEOUT_MS)
    		.build();
    	
        return HttpClients.custom().useSystemProperties().setDefaultRequestConfig(requestConfig).build();
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

        HttpPost httpPost = new HttpPost(getTokenSite() + iTokenVerifyPath);
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
     * Fetches the token verification response from the cache
     * and returns it if it hasn't expired.
     *
     * @param cachingKey The key to look for in the cache.
     *
     * @return AllowedResponse from the cache.
     */
    private AllowedResponse getTokenResponseFromCache(String cachingKey) {
        AllowedResponse cachedResponse = allowedResponseSecondaryCache == null ? cTokenResponseCache.getIfPresent(cachingKey) : allowedResponseSecondaryCache.getValue(cachingKey);

        if (cachedResponse != null) {
            if (!cachedResponse.isExpired()) {
                return cachedResponse;
            }
            //Expired, so remove it from cache and return null
            removeCachedTokenResponse(cachingKey);
        }
        return null;
    }

    /**
     * Caching a token response.
     *
     * @param cachingKey The key to use for the caching.
     * @param allowedResponse The response to cache.
     */
    private void cacheTokenResponse(String cachingKey, AllowedResponse allowedResponse) {
        if (cachingKey != null) {
        	if (allowedResponseSecondaryCache != null) {
        		allowedResponseSecondaryCache.putValue(cachingKey, allowedResponse);
        	} else {
                cTokenResponseCache.put(cachingKey, allowedResponse);
        	}
        }
    }

    /**
     * Removing a cached token response.
     *
     * @param cachingKey The key to remove from the cache.
     */
    private void removeCachedTokenResponse(String cachingKey) {
        if (cachingKey != null) {
        	if (allowedResponseSecondaryCache != null) {
        		allowedResponseSecondaryCache.removeValue(cachingKey);
        	} else {
        		cTokenResponseCache.invalidate(cachingKey);
        	}
        }
    }
}

class ServiceUnauthorizedException extends Exception {
}
