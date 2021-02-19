package com.coupa.sand;

import static org.junit.Assert.*;

import org.junit.Test;

public class AllowedResponseTest {

  @Test
  public void testIsExpired() {
    AllowedResponse ar = new AllowedResponse(false);
    
    assertNull(ar.getExp());
    assertFalse(ar.isExpired());
    
    ar.setExp("1980-02-09T10:05:53.637844877Z");
    assertTrue(ar.isExpired());

    ar.setExp("3000-02-09T10:05:53.637844877Z");
    assertFalse(ar.isExpired());
    
    ar.setExp("1980-02-09T20:40:12.055455+08:00");
    assertTrue(ar.isExpired());

    ar.setExp("3000-02-09T20:40:12.055455+08:00");
    assertFalse(ar.isExpired());
  }

}
