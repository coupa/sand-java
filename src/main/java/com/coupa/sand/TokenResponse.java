package com.coupa.sand;

import java.io.Serializable;
import java.util.Map;

/**
 *  This class represents a token response when getting a token.
 *
 * @author John Wu
 */
public class TokenResponse implements Serializable {
	
	private static final long serialVersionUID = -742168469210621455L;
	
  private static final String ACCESS_TOKEN = "access_token";
  private static final String EXPIRES_IN = "expires_in";
  private static final String SCOPE = "scope";
  private static final String TOKEN_TYPE = "token_type";

  private static final long DEFAULT_TOKEN_EXPIRES_IN_SECONDS = 3_599L;

  private String token;
  private long expiresIn;
  private String[] scopes;
  private String tokenType;
  
  private long expiresAt;

  /**
   * Constructor that will take a map response and set all information
   *
   * Example data:
   * {"access_token":"xxxxxxxxxxxxx",
   *  "expires_in":3599,
   *  "scope":"myscope",
   *  "token_type":"bearer"}
   *
   * @param mapResponse a Map with the whole response body from the SAND server.
   */
  TokenResponse(Map<String, Object> mapResponse) {
      token = (String) mapResponse.get(ACCESS_TOKEN);
      tokenType = (String) mapResponse.get(TOKEN_TYPE);

      String scope = (String) mapResponse.get(SCOPE);
      scopes = scope != null ? scope.split(" ") : new String[] {};

      Object expire = mapResponse.get(EXPIRES_IN);
      setExpiresAt(System.currentTimeMillis(), expire);
  }

  public boolean isExpired() {
	  return System.currentTimeMillis() > expiresAt;
  }

  public String getToken() {
      return token;
  }

  public void setToken(String token) {
      this.token = token;
  }

  public String[] getScopes() {
      return scopes;
  }

  public void setScopes(String[] scopes) {
      this.scopes = scopes;
  }

  public long getExpiresIn() {
      return expiresIn;
  }

  public String getTokenType() {
      return tokenType;
  }

  public void setTokenType(String tokenType) {
      this.tokenType = tokenType;
  }
  
  public void setExpiresAt(long currentTime, Object expire) {
      if (expire instanceof Long) {
          expiresIn = (long) expire;
      } else if (expire instanceof String) {
          expiresIn = Long.parseLong((String) expire);
      } else {
          expiresIn = DEFAULT_TOKEN_EXPIRES_IN_SECONDS;
      }
      expiresAt = currentTime + expiresIn * 1_000L;
  }
  
  public long getExpiresAt() {
      return expiresAt;
  }
}
