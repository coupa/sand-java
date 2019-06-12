package com.coupa.sand;

import java.util.ArrayList;
import java.util.Map;

/**
 *  This class creates a response that a Service returns
 *  when checking if a request has access.
 *
 * @author Mattias Kjetselberg
 */
public class AllowedResponse {
    private static final String RESPONSE_FIELD_ALLOWED = "allowed";
    private static final String RESPONSE_FIELD_SUB = "sub";
    private static final String RESPONSE_FIELD_SCOPES = "scopes";
    private static final String RESPONSE_FIELD_ISS = "iss";
    private static final String RESPONSE_FIELD_AUD = "aud";
    private static final String RESPONSE_FIELD_IAT = "iat";
    private static final String RESPONSE_FIELD_EXP = "exp";
    private static final String RESPONSE_FIELD_EXT = "ext";

    private boolean iAllowed = false;
    private String iSub = null;
    private String[] iScopes = null;
    private String iIss = null;
    private String iAud = null;
    private String iIat = null;
    private String iExp = null;
    private String iExt = null;

    /**
     * Constructor that will just set if the response is allowed or not
     * so that the isAllowed() function can be called on the response.
     *
     * @param allowed if the AllowedResponse is true or false.
     */
    AllowedResponse(boolean allowed) {
        iAllowed = allowed;
    }

    /**
     * Constructor that will take a map response and set all information
     * if the response is allowed = true, otherwise just allowed = false.
     *
     * @param mapResponse a Map with the whole response body from the SAND server.
     */
    AllowedResponse(Map<String, Object> mapResponse) {
        Object allowedObject = mapResponse.get(RESPONSE_FIELD_ALLOWED);
        boolean allowed;

        if (allowedObject instanceof Boolean) {
            allowed = (boolean)allowedObject;
        }
        else if (allowedObject instanceof String){
            allowed = "true".equalsIgnoreCase(allowedObject.toString());
        }
        else {
            allowed = false;
        }

        if (allowed) {
            iAllowed = true;
            iSub = (String)mapResponse.get(RESPONSE_FIELD_SUB);
            Object scopesObject = mapResponse.get(RESPONSE_FIELD_SCOPES);

            if (scopesObject instanceof ArrayList) {
                iScopes = ((ArrayList<String>)scopesObject).toArray(new String[0]);
            }
            else if (scopesObject instanceof String[]) {
                iScopes = (String[])scopesObject;
            }

            iIss = (String)mapResponse.get(RESPONSE_FIELD_ISS);
            iAud = (String)mapResponse.get(RESPONSE_FIELD_AUD);
            iIat = (String)mapResponse.get(RESPONSE_FIELD_IAT);
            iExp = (String)mapResponse.get(RESPONSE_FIELD_EXP);
            iExt = (String)mapResponse.get(RESPONSE_FIELD_EXT);
        }
        else {
            iAllowed = false;
        }
    }

    public boolean isAllowed() {
        return iAllowed;
    }

    public void setAllowed(boolean allowed) {
        iAllowed = allowed;
    }

    public String getSub() {
        return iSub;
    }

    public void setSub(String sub) {
        iSub = sub;
    }

    public String[] getScopes() {
        return iScopes;
    }

    public void setScopes(String[] scopes) {
        iScopes = scopes;
    }

    public String getIss() {
        return iIss;
    }

    public void setIss(String iss) {
        iIss = iss;
    }

    public String getAud() {
        return iAud;
    }

    public void setAud(String aud) {
        iAud = aud;
    }

    public String getIat() {
        return iIat;
    }

    public void setIat(String iat) {
        iIat = iat;
    }

    public String getExp() {
        return iExp;
    }

    public void setExp(String exp) {
        iExp = exp;
    }

    public String getExt() {
        return iExt;
    }

    public void setExt(String ext) {
        iExt = ext;
    }
}
