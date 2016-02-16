/*
 *
 *   Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package org.wso2.carbon.apimgt.sciquest.keymanager;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Set;

/**
 * This class provides the implementation to use "Apis" {@link "https://github.com/OAuth-Apis/apis"} for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class APIManagerOAuthClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(APIManagerOAuthClient.class);

    private KeyManagerConfiguration configuration;

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param configuration Configuration as a {@link org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration}
     */

    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {

        this.configuration = configuration;
    }

    /**
     * This method will Register the client in Authorization Server.
     *
     * @param oauthAppRequest this object holds all parameters required to register an OAuth Client.
     */

    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

        log.warn("The Operation [Create OAuth Application] is not supported by the OAuth 2 Server");

        return null;
    }

    /**
     * This method will update an existing OAuth Client.
     *
     * @param oauthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException
     */

    public OAuthApplicationInfo updateApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

       log.warn("The Operation [Update OAuth Application] is not supported by the OAuth 2 Server");

        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @throws APIManagementException
     */

    public void deleteApplication(String consumerKey) throws APIManagementException {
        log.warn("The Operation [Delete OAuth Application] is not supported by the OAuth 2 Server");
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException
     */

    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled())   {
            log.debug("The Operation [Retrieve OAuth Application details] is not supported by the OAuth 2 Server");
        }

        // NO Client Registration URL provided to query,

        OAuthApplicationInfo info = new OAuthApplicationInfo();
        info.setClientId(consumerKey);

        return info;

    }


    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

        log.info("Calling OAuth Server for generating Access Token");

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        String tokenEndpoint = config.getParameter(ClientConstants.TOKEN_URL);

        HttpPost httpPost = new HttpPost(tokenEndpoint.trim());

        HttpClient httpClient = new DefaultHttpClient();

        try {
            String jsonPayload = "grant_type=client_credentials";

            httpPost.setEntity(new StringEntity(jsonPayload, ClientConstants.UTF_8));
            httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.URL_ENCODED_CONTENT_TYPE);
            httpPost.setHeader(ClientConstants.ACCEPT, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);

            String encodedSecret =
                    Base64.encode(new String(tokenRequest.getClientId() + ":" + tokenRequest.getClientSecret()).getBytes());

            httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BASIC + encodedSecret);

            HttpResponse response = httpClient.execute(httpPost);
            int responseCode = response.getStatusLine().getStatusCode();

            if (HttpStatus.SC_OK == responseCode) {
                HttpEntity entity = response.getEntity();
                BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));
                JSONObject parsedObject = getParsedObjectByReader(reader);

                return getAccessTokenFromResponse(parsedObject);
            } else {
                handleException("Some thing wrong here while retrieving new token " +
                                "HTTP Error response code is " + responseCode);
            }

        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request  to OAuth Provider. " + e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } catch (ParseException e)  {
            handleException("Error while parsing response json " + e.getMessage(), e);
        }

        return null;
    }


    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        String introspectionURL = config.getParameter(ClientConstants.INTROSPECTION_URL);
        String introspectionConsumerKey = config.getParameter(ClientConstants.INTROSPECTION_CK);
        String introspectionConsumerSecret = config.getParameter(ClientConstants.INTROSPECTION_CS);
        String encodedSecret = Base64.encode(new String(introspectionConsumerKey + ":" + introspectionConsumerSecret)
                                                     .getBytes());

        BufferedReader reader = null;

        try {
            URIBuilder uriBuilder = new URIBuilder(introspectionURL);
            uriBuilder.addParameter("access_token", accessToken);
            uriBuilder.build();

            HttpGet httpGet = new HttpGet(uriBuilder.build());
            HttpClient client = new DefaultHttpClient();

            httpGet.setHeader("Authorization", "Basic " + encodedSecret);
            HttpResponse response = client.execute(httpGet);
            int responseCode = response.getStatusLine().getStatusCode();

            if (log.isDebugEnabled())   {
                log.debug("HTTP Response code : " + responseCode);
            }

            // Response Format from OAuth 2 Server

            /*{
                "audience":"MappedClient",
                    "scopes":[
                        "test"
                    ],
                    "principal":{
                        "name":"mappedclient",
                        "roles":[

                        ],
                        "groups":[

                        ],
                        "adminPrincipal":false,
                        "attributes":{

                        }
                    },
                    "expires_in":1433059160531
            }*/

            HttpEntity entity = response.getEntity();
            JSONObject parsedObject;
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (HttpStatus.SC_OK == responseCode) {
                //pass bufferReader object  and get read it and retrieve  the parsedJson object
                parsedObject = getParsedObjectByReader(reader);
                if (parsedObject != null) {

                    Map valueMap = parsedObject;
                    Object principal = valueMap.get("principal");

                    if (principal == null) {
                        tokenInfo.setTokenValid(false);
                        return tokenInfo;
                    }
                    Map principalMap = (Map) principal;
                    String clientId = (String) principalMap.get("name");
                    Long expiryTimeString = (Long) valueMap.get("expires_in");

                    // Returning false if mandatory attributes are missing.
                    if (clientId == null || expiryTimeString == null) {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
                        return tokenInfo;
                    }

                    long currentTime = System.currentTimeMillis();
                    long expiryTime = expiryTimeString;
                    if (expiryTime > currentTime) {
                        tokenInfo.setTokenValid(true);
                        tokenInfo.setConsumerKey(clientId);
                        tokenInfo.setValidityPeriod(expiryTime - currentTime);
                        // Considering Current Time as the issued time.
                        tokenInfo.setIssuedTime(currentTime);
                        JSONArray scopesArray = (JSONArray) valueMap.get("scopes");

                        if (scopesArray != null && !scopesArray.isEmpty()) {

                            String[] scopes = new String[scopesArray.size()];
                            for (int i = 0; i < scopes.length; i++) {
                                scopes[i] = (String) scopesArray.get(i);
                            }
                            tokenInfo.setScope(scopes);
                        }
                    } else {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                        return tokenInfo;
                    }

                } else {
                    log.error("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    return tokenInfo;
                }
            }//for other HTTP error codes we just pass generic message.
            else {
                log.error("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                return tokenInfo;
            }

        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request  to OAuth Provider. " + e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            handleException("Error occurred while building URL with params." + e.getMessage(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(reader);
        }

        return tokenInfo;
    }


    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }


    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param appInfoRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException
     */

    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest)
            throws APIManagementException {

        log.info("Client OAuth application creation not supported in OAuth Server");

        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
        return oAuthApplicationInfo;
    }


    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }


    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }


    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }


    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }


    public void deleteMappedApplication(String s) throws APIManagementException {

    }


    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }


    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }


    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    private AccessTokenInfo getAccessTokenFromResponse(JSONObject map)  {

        //{"scope":"test","access_token":"b32875ac-bf5d-40c4-838d-a1c69b13479c","token_type":"bearer","expires_in":3600}

        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        tokenInfo.setAccessToken((String)map.get("access_token"));
        tokenInfo.setValidityPeriod(Long.valueOf((String)map.get("expires_in")));
        tokenInfo.setScope(new String[]{(String)map.get("scope")});
        return tokenInfo;

    }


}
