package com.coupa.sand;

/**
 *  Utility class.
 *
 * @author John Wu
 */
public class Util {
	
	/**
	 * Checks if any of the string parameter is empty (null or "")
	 * @param strs
	 * @return true if any string is empty or null.
	 */
	public static boolean hasEmpty(String... strs) {
		if (strs == null || strs.length == 0) {
			return true;
		}
		for (String str : strs) {
			if (str == null || str.isEmpty()) {
				return true;
			}
		}
		return false;
	}
}
