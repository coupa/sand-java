package com.coupa.sand;

import static org.junit.Assert.*;

import org.junit.Test;

public class UtilTest {

  @Test
  public void testHasEmpty() {
    assertTrue(Util.hasEmpty());
    assertTrue(Util.hasEmpty(""));
    assertTrue(Util.hasEmpty(null));
    String s = null;
    assertTrue(Util.hasEmpty(s));
    

    assertTrue(Util.hasEmpty("hi", null));
    assertTrue(Util.hasEmpty("hi", ""));
    assertTrue(Util.hasEmpty("", null));
    assertTrue(Util.hasEmpty("", "hi"));
    assertTrue(Util.hasEmpty("", ""));
    assertTrue(Util.hasEmpty("2", "1", ""));
    
    assertFalse(Util.hasEmpty(" ", "1"));
    assertFalse(Util.hasEmpty("2", "1"));
  }
}
