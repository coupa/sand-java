package com.coupa.sand;

import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.Assert.assertEquals;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.apache.http.auth.AuthenticationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class CacheIntegrationTest {

	private final Gson gson = new GsonBuilder().create();
	
	@Rule
	public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());
	
	@Before
	public void before() {
		System.setProperty(SecondaryCache.ENV_SAND_CACHE_REDIS_PASSWORD, "foobared");
	}

	@Test
	public void testTokenCache() throws AuthenticationException {

		/*
		 * Create a caching key based on current runtime
		 */
		String cachingKey = Long.toString(System.currentTimeMillis());

		/*
		 * Configure WireMock Stubs for token request
		 */
		stubFor(post("/oauth2/token").willReturn(okJson(createTokenResponseJson("s3f7MWUjLFzg3CHqiDBXKjzwoTqcSqqv", 120))));

		String tokenUrl = wireMockRule.baseUrl();

		Client client = new Client("client_id", "supersecret", tokenUrl);
		client.genericRequest(tokenUrl, new String[] { "scope1", "scope2" }, 1, new Function<String, GenericResponse<String>>() {
			@Override
			public GenericResponse<String> apply(String token) {
				Assert.assertEquals("s3f7MWUjLFzg3CHqiDBXKjzwoTqcSqqv", token);
				return null;
			}
		});

	}

	@Test
	public void testServiceTokenCache() throws AuthenticationException {

		/*
		 * Create a caching key based on current runtime
		 */
		String cachingKey = Long.toString(System.currentTimeMillis());
		
		/*
		 * Configure WireMock Stubs for token request and authorization check.
		 */
		String now = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
		String expires = OffsetDateTime.now().plusSeconds(10L).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

		stubFor(post("/oauth2/token").willReturn(okJson(createTokenResponseJson("Iq13JzfK7jc6JabGmtaRao15J6eAxImU", 120))));
		
		stubFor(post("/warden/token/allowed").willReturn(okJson(createAllowedResponseJson("token",
				new String[] { "myscope" }, "hydra.localhost", "service", now, expires, null, true))));

		/*
		 * Initiate Requests for service access.
		 */
		String tokenUrl = wireMockRule.baseUrl();

		Service service = new Service("client_id", "supersecret", tokenUrl, "resource");
		
		for (int i = 1; i <= 3; i++) {
			
			String returnedToken = service.getToken(cachingKey, new String[] { "scope1" }, 0);
			
			AllowedResponse allowedResponse = service.checkToken(returnedToken,
					new VerificationOptions(new String[] { "scope1", "scope2" }, "read", "resource"));

			assertEquals(allowedResponse.isAllowed(), true);
			
			try {
				Thread.sleep(6000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			
		}

	}

	private String createTokenResponseJson(String accessToken, int expiresIn) {
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("access_token", accessToken);
		data.put("expires_in", expiresIn);
		return gson.toJson(data);
	}

	private String createAllowedResponseJson(String sub, String[] scopes, String iss, String aud, String iat,
			String exp, String ext, boolean allowed) {
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("sub", sub);
		data.put("scopes", scopes);
		data.put("iss", iss);
		data.put("aud", aud);
		data.put("iat", iat);
		data.put("exp", exp);
		data.put("ext", ext);
		data.put("allowed", allowed);
		return gson.toJson(data);

	}


}
