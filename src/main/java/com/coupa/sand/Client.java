package com.coupa.sand;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.minidev.json.JSONObject;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 *  This class creates a Client for authentication with a SAND server,
 *  to make API calls to a Service.
 *
 * @author Mattias Kjetselberg
 */
public class Client {
    private static final Logger LOGGER = LoggerFactory.getLogger(Client.class);
    private static final String DEFAULT_CACHE_ROOT = "sand";
    private static final String DEFAULT_CLIENT_CACHE_TYPE = "resources";

    protected static final String DEFAULT_TOKEN_PATH = "/oauth2/token";
    protected static final int DEFAULT_RETRY_COUNT = 5;

    String iClientId = null;
    String iClientSecret = null;
    String iTokenSite = null;
    String iTokenPath = DEFAULT_TOKEN_PATH;
    String iCacheRoot = DEFAULT_CACHE_ROOT;
    String iCacheType = DEFAULT_CLIENT_CACHE_TYPE;

    /**
     * Cache to avoid repeated calls to SAND authentication server.
     * Tokens are cached for 1 hour.
     */
    private static final Cache<String, TokenResponse> cTokenCache =
            CacheBuilder
            .newBuilder()
            .concurrencyLevel(4)
            .maximumSize(1000)
            .expireAfterWrite(1L, TimeUnit.HOURS)
            .build();

    /**
     * Constructor that sets the default tokenPath
     *
     * @param clientId The ID of the Client that's registered in the SAND server.
     * @param secret The Secret of the Client that's registred in the SAND server.
     * @param tokenSite The URL to the SAND server.
     */
    public Client(String clientId, String clientSecret, String tokenSite) {
        this(clientId, clientSecret, tokenSite, DEFAULT_TOKEN_PATH);
    }

    /**
     * Constructor
     *
     * @param clientId The ID of the Client that's registered in the SAND server.
     * @param secret The Secret of the Client that's registred in the SAND server.
     * @param tokenSite The URL to the SAND server.
     * @param tokenPath The endpoint on the SAND server to request an oauth token.
     */
    public Client(String clientId, String clientSecret, String tokenSite, String tokenPath) {
        if (Util.isEmpty(clientId, clientSecret, tokenSite, tokenPath)) {
            throw new IllegalArgumentException("Client credentials and token site and path are all required");
        }
        iClientId = clientId;
        iClientSecret = clientSecret;
        iTokenSite = tokenSite;
        iTokenPath = tokenPath;
    }

    /**
     * Makes a Client request to a Service by applying a token to the requestFunction parameter.
     * Will fetch new tokens and perform retries (at least one) if the response is 401.
     * Will use the default retry count;
     *
     * @param keyForCaching Key that will be used to build a caching key for storing request tokens.
     * @param scopes The scopes that the token will be created for.
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
            Function<String, HttpResponse> requestFunction) {

        return request(keyForCaching, scopes, DEFAULT_RETRY_COUNT, requestFunction);
    }

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
            Function<String, HttpResponse> requestFunction) {

        if (requestFunction == null || Util.isEmpty(keyForCaching)) {
            return null;
        }

        int requestRetry = 0;
        retries = clientRequestRetryCount(retries);
        String cachingKey = cacheKey(keyForCaching, scopes, null, null);

        HttpResponse response = null;
        int statusCode = accessDeniedStatusCode();
        String token;

        do {
            if (requestRetry > 0) {
                if (requestRetry > retries) {
                    return null;
                }
                removeCachedToken(cachingKey);
                long secondsSleep = (long)Math.pow(2, requestRetry);

                try {
                    Thread.sleep(1_000L * secondsSleep);
                } catch (InterruptedException e) {
                    LOGGER.error("Sleep before retrying SAND authentication was interrupted.", e);
                }
            }

            token = getToken(keyForCaching, scopes, retries);

            if (token != null) {
                response = requestFunction.apply(token);

                if (response != null) {
                    statusCode = response.getStatusLine().getStatusCode();
                }
            }

            requestRetry++;
        } while (statusCode == accessDeniedStatusCode());

        return response;
    }

    /**
     * Gets an access token by first checking the cache
     * and then doing a oauth token request to the SAND server.
     * If an oauth token is fetched, it will be cached.
     *
     * @param keyForCaching The key to use for checking the cache for a token or cache a token.
     * @param scopes The scopes to fetch a token for.
     * @param retries Number of retires to try fetching a token.
     *
     * @return String token.
     */
    public String getToken(String keyForCaching, String[] scopes, int retries) {
        TokenResponse token = getOAuthToken(keyForCaching, scopes, retries);
        return token.getToken();
    }

    /**
     * Gets an access token by first checking the cache
     * and then doing a oauth token request to the SAND server.
     * If an oauth token is fetched, it will be cached.
     *
     * @param keyForCaching The key to use for checking the cache for a token or cache a token.
     * @param scopes The scopes to fetch a token for.
     * @param retries Number of retires to try fetching a token.
     *
     * @return TokenResponse token.
     */
    public TokenResponse getOAuthToken(String keyForCaching, String[] scopes, int retries) {
        String cachingKey = cacheKey(keyForCaching, scopes, null, null);

        TokenResponse item = getFromCache(cachingKey);
        if (item != null) {
            return item;
        }

        item = tokenRequest(scopes, retries);
        if (item != null) {
            cacheToken(cachingKey, item);
        }
        return item;
    }

    /**
     * Makes a request to the SAND server for an access token.
     *
     * @param scopes The scopes to fetch a token for.
     * @param retries Number of retries to fetch a token.
     *
     * @return TokenResponse with token information.
     */
    public TokenResponse tokenRequest(String[] scopes, int retries) {
        TokenRequest tokenRequest = createTokenRequest(scopes);

        if (tokenRequest == null) {
            return null;
        }

        HTTPResponse tokenHTTPResp;
        int statusCode;
        int requestRetry = 0;
        retries = tokenRequestRetryCount(retries);

        do {
            if (requestRetry > 0) {
                if (requestRetry > retries) {
                    return null;
                }

                long secondsSleep = (long) Math.pow(2, requestRetry);

                try {
                    Thread.sleep(1_000L * secondsSleep);
                } catch (InterruptedException e) {
                    LOGGER.error("Sleep before retrying SAND authentication was interrupted.", e);
                }
            }

            tokenHTTPResp = sendTokenRequest(tokenRequest);

            if (tokenHTTPResp == null) {
                return null;
            }

            statusCode = tokenHTTPResp.getStatusCode();

            if (statusCode == HttpStatus.SC_OK) {
                try {
                    JSONObject json = tokenHTTPResp.getContentAsJSONObject();
                    if (json != null) {
                        return new TokenResponse(json);
                    }
                    return null;
                } catch (ParseException e) {
                    LOGGER.error("Could not parse the oauth token response", e);
                }
            } else {
                requestRetry++;
            }
        } while (statusCode != HttpStatus.SC_OK);

        return null;
    }

    /**
     * Requesting a token.
     *
     * @param tokenRequest token request to send.
     *
     * @return HTTPResponse
     */
    private HTTPResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            return tokenRequest.toHTTPRequest().send();
        } catch (SerializeException | IOException e) {
            LOGGER.error("Error sending token request: ", e);
        }

        return null;
    }

    /**
     * Creates a token request for the configured Client with the specified scopes.
     *
     * @param scopes The scopes to request a token for.
     *
     * @return TokenRequest
     */
    private TokenRequest createTokenRequest(String[] scopes) {
        try {
            return new TokenRequest(
                    new URI(getTokenURL()),
                    new ClientSecretBasic(getClientID(), getClientSecret()),
                    new ClientCredentialsGrant(),
                    new Scope(scopes));
        } catch (URISyntaxException e) {
            LOGGER.error("Configured Client Token URL is wrong.", e);

            return null;
        }
    }

    private TokenResponse getFromCache(String cachingKey) {
        TokenResponse item = null;

        if (!Util.isEmpty(cachingKey)) {
            item = cTokenCache.getIfPresent(cachingKey);
            if (item != null && item.isExpired()) {
                removeCachedToken(cachingKey);
                item = null;
            }
        }
        return item;
    }

    /**
     * Caches a token with added information about when it will expire.
     * Will use the tokens expires_in information or a default of 1 hour.
     *
     * @param cachingKey The key to use for caching.
     * @param token The token to cache.
     */
    private void cacheToken(String cachingKey, TokenResponse token) {
        if (!Util.isEmpty(cachingKey) && token != null) {
            cTokenCache.put(cachingKey, token);
        }
    }

    /**
     * Removing a cached token.
     *
     * @param cachingKey The key to remove from the cache.
     */
    private void removeCachedToken(String cachingKey) {
        if (!Util.isEmpty(cachingKey)) {
            cTokenCache.invalidate(cachingKey);
        }
    }

    /**
     * cacheKey builds the cache key in the format:
     * <iCacheRoot>/<iCacheType>/<cachingKey>/<scope>_<scope>.../<resource>/<action>
     *
     * @param cachingKey Key that will be used to build the caching key.
     * @param scopes Scopes that will ve used to build the caching key.
     * @param resource Resource that will be used to build the caching key.
     * @param action Action that will be used to build the caching key.
     *
     * @return String a key to be used for caching.
     */
    protected String cacheKey(String cachingKey, String[] scopes, String resource, String action) {
        StringBuilder sb = new StringBuilder();
        sb.append(iCacheRoot);
        sb.append("/");
        sb.append(iCacheType);
        sb.append("/");
        sb.append(cachingKey);

        if (scopes.length > 0) {
            sb.append("/");
            sb.append(String.join("_", scopes));
        }

        if (!Util.isEmpty(resource)) {
            sb.append("/");
            sb.append(resource);
        }

        if (!Util.isEmpty(action)) {
            sb.append("/");
            sb.append(action);
        }

        return sb.toString();
    }

    /**
     * When services successfully check tokens with authentication service but the
     * token is denied access, they must use this method to set the response code.
     *
     * @return int for the unauthorized status code.
     */
    public static int accessDeniedStatusCode() {
        return HttpStatus.SC_UNAUTHORIZED;
    }

    /**
     * When services raise error when checking a request's token, they must use
     * this method to set the response code.
     *
     * @return int for bad gateway status code.
     */
    public static int errorStatusCode() {
        return HttpStatus.SC_BAD_GATEWAY;
    }

    /**
     * For client requests to services, the retry must be at least 1 in case that the
     * token is expired, then a retry would make the client get a new token.
     *
     * @param retries Number of retries that's been configured.
     *
     * @return int Number of retries count that will be used.
     */
    private int clientRequestRetryCount(int retries) {
        if (retries < 1) {
            retries = DEFAULT_RETRY_COUNT;
        }

        return retries;
    }

    /**
     * For requests to get SAND access tokens, we allow 0 retry if the caller doesn't
     * want to retry. Specifying a negative number will make it use the default retry count.
     *
     * @param retries Number of retries that's been configured.
     *
     * @return int Number of retries count that will be used.
     */
    private int tokenRequestRetryCount(int retries) {
        if (retries < 0) {
            retries = DEFAULT_RETRY_COUNT;
        }

        return retries;
    }

    public String getTokenURL() {
        return iTokenSite + iTokenPath;
    }

    public String getTokenSite() {
        return iTokenSite;
    }

    public void setTokenSite(String tokenSite) {
        iTokenSite = tokenSite;
    }

    public String getTokenPath() {
        return iTokenPath;
    }

    public void setTokenPath(String tokenPath) {
        iTokenPath = tokenPath;
    }

    public ClientID getClientID() {
        return new ClientID(iClientId);
    }

    public String getClientId() {
        return iClientId;
    }

    public void setClientId(String clientId) {
        iClientId = clientId;
    }

    public Secret getClientSecret() {
        return new Secret(iClientSecret);
    }

    public void setClientSecret(String clientSecret) {
        iClientSecret = clientSecret;
    }

    public String getCacheRoot() {
        return iCacheRoot;
    }

    public void setCacheRoot(String cacheRoot) {
        iCacheRoot = cacheRoot;
    }

    public String getCacheType() {
        return iCacheType;
    }

    public void setCacheType(String cacheType) {
        iCacheType = cacheType;
    }
}
