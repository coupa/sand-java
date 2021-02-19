package com.coupa.sand;

import static org.junit.Assert.*;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

public class TokenResponseTest {
  HashMap<String, Object> data;
  
  @Before
  public void setUp() throws Exception {
    data = new HashMap<String, Object>();
    data.put("access_token", "abcde");
    data.put("expires_in", 3599L);
    data.put("scope", "some_scope");
    data.put("token_type", "bearer");
  }

  @Test
  public void testIsExpired() {
    TokenResponse tr = new TokenResponse(data);
    assertFalse(tr.isExpired());
    
    data.put("expires_in", -3599L);
    tr = new TokenResponse(data);
    assertTrue(tr.isExpired());
  }

  @Test
  public void testSetExpiresAt() {
    TokenResponse tr = new TokenResponse(data);
    
    tr.setExpiresAt(0L, 3L);
    assertEquals(tr.getExpiresIn(), 3L);
    assertEquals(tr.getExpiresAt(), 3000L);
  }

}
