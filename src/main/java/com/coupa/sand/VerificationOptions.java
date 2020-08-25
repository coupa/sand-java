package com.coupa.sand;

import java.util.HashMap;
import java.util.Map;

public class VerificationOptions {
    String[] iTargetScopes;
    String iAction;
    String iResource;
    Map<String, String> iContext = new HashMap<>();
    int iNumRetries;

    /**
     * Constructor that will throw an IllegalArgumentException
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
            int numRetries) {

        if (Util.hasEmpty(resource)) {
            throw new IllegalArgumentException("This Service has no configured resource");
        }

        iTargetScopes = targetScopes;
        iResource = resource;
        iAction = action;
        iNumRetries = numRetries;
    }

    /**
     * Constructor that will throw an AuthenticationException
     * if the resource parameter is empty.
     *
     * @param targetScopes The scopes to verify the token against.
     * @param action The action to verify the token against.
     * @param resource The resource to verify the token against.
     */
    public VerificationOptions(String[] targetScopes,
            String action,
            String resource) {
        this(targetScopes, action, resource, -1);
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
