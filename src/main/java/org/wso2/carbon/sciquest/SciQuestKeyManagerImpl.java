package org.wso2.carbon.sciquest;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;

import java.util.Map;
import java.util.Set;

/**
 * Created by abimaran on 2/12/16.
 */
    public class SciQuestKeyManagerImpl extends AbstractKeyManager {
    @Override
        public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return null;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return null;
    }

    @Override
    public void deleteApplication(String s) throws APIManagementException {

    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String s) throws APIManagementException {
        return null;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return null;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
        return null;
    }

    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return null;
    }

    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {

    }

    @Override
    public boolean registerNewResource(API api, Map map) throws APIManagementException {
        return false;
    }

    @Override
    public Map getResourceByApiId(String s) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map map) throws APIManagementException {
        return false;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String s) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }
}
