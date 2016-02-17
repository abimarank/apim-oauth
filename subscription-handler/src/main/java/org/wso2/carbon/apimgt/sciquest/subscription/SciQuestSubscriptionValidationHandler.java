package org.wso2.carbon.apimgt.sciquest.subscription;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.apimgt.keymgt.handlers.AbstractKeyValidationHandler;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 *
 *
 */

public class SciQuestSubscriptionValidationHandler extends AbstractKeyValidationHandler {

    private static final Log log = LogFactory.getLog(SciQuestSubscriptionValidationHandler.class);

    @Override
    public boolean validateSubscription(TokenValidationContext validationContext) throws APIKeyMgtException {

        if (log.isDebugEnabled())   {
            log.debug("By default all the users are subscribed to all the APIs, not validating anything");
        }

        // By default all the users are subscribed to all the APIs, no need to validate

        return true;
    }

    public boolean validateToken(TokenValidationContext validationContext) throws APIKeyMgtException {

        // Copied the functionality from DefaultKeyValidationHandler class in
        // org.wso2.carbon.apimgt:org.wso2.carbon.apimgt.keymgt:5.0.3 dependency

        // If validationInfoDTO is taken from cache, validity of the cached infoDTO is checked with each request.
        if (validationContext.isCacheHit()) {
            APIKeyValidationInfoDTO infoDTO = validationContext.getValidationInfoDTO();

            checkClientDomainAuthorized(infoDTO, validationContext.getClientDomain());
            boolean tokenExpired = APIUtil.isAccessTokenExpired(infoDTO);
            if (tokenExpired) {
                infoDTO.setAuthorized(false);
                infoDTO.setValidationStatus(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                log.debug("Token " + validationContext.getAccessToken() + " expired.");
                return false;
            } else {
                return true;
            }
        }

        AccessTokenInfo tokenInfo;

        try {

            // Obtaining details about the token.
            tokenInfo = KeyManagerHolder.getKeyManagerInstance().getTokenMetaData(validationContext.getAccessToken());

            if (tokenInfo == null) {
                return false;
            }

            // Setting TokenInfo in validationContext. Methods down in the chain can use TokenInfo.
            validationContext.setTokenInfo(tokenInfo);

            APIKeyValidationInfoDTO apiKeyValidationInfoDTO = new APIKeyValidationInfoDTO();
            validationContext.setValidationInfoDTO(apiKeyValidationInfoDTO);

            if (!tokenInfo.isTokenValid()) {
                apiKeyValidationInfoDTO.setAuthorized(false);
                if (tokenInfo.getErrorcode() > 0) {
                    apiKeyValidationInfoDTO.setValidationStatus(tokenInfo.getErrorcode());
                }else {
                    apiKeyValidationInfoDTO.setValidationStatus(APIConstants
                                                                        .KeyValidationStatus.API_AUTH_GENERAL_ERROR);
                }
                return false;
            }

            apiKeyValidationInfoDTO.setAuthorized(tokenInfo.isTokenValid());
            apiKeyValidationInfoDTO.setEndUserName(tokenInfo.getEndUserName());
            apiKeyValidationInfoDTO.setConsumerKey(tokenInfo.getConsumerKey());
            apiKeyValidationInfoDTO.setIssuedTime(tokenInfo.getIssuedTime());
            apiKeyValidationInfoDTO.setValidityPeriod(tokenInfo.getValidityPeriod());

            if (tokenInfo.getScopes() != null) {
                Set<String> scopeSet = new HashSet<String>(Arrays.asList(tokenInfo.getScopes()));
                apiKeyValidationInfoDTO.setScopes(scopeSet);
            }

        } catch (APIManagementException e) {
            log.error("Error while obtaining Token Metadata from Authorization Server", e);
            throw new APIKeyMgtException("Error while obtaining Token Metadata from Authorization Server");
        }

        return tokenInfo.isTokenValid();
    }

    public boolean validateScopes(TokenValidationContext validationContext) throws APIKeyMgtException {

        // Copied the functionality from DefaultKeyValidationHandler class in
        // org.wso2.carbon.apimgt:org.wso2.carbon.apimgt.keymgt:5.0.3 dependency

        if(validationContext.isCacheHit()){
            return true;
        }

        OAuth2ScopeValidator scopeValidator = OAuthServerConfiguration.getInstance().getoAuth2ScopeValidator();


        APIKeyValidationInfoDTO apiKeyValidationInfoDTO = validationContext.getValidationInfoDTO();

        if(apiKeyValidationInfoDTO == null){
            throw new APIKeyMgtException("Key Validation information not set");
        }

        String[] scopes = null;
        Set<String> scopesSet = apiKeyValidationInfoDTO.getScopes();

        if (scopesSet != null && !scopesSet.isEmpty()) {
            scopes = scopesSet.toArray(new String[scopesSet.size()]);
            if (log.isDebugEnabled() && scopes != null) {
                StringBuffer scopeList = new StringBuffer();
                for (String scope : scopes) {
                    scopeList.append(scope + ",");
                }
                scopeList.deleteCharAt(scopeList.length() - 1);
                log.debug("Scopes allowed for token : " + validationContext.getAccessToken() + " : " + scopeList.toString());
            }
        }

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(apiKeyValidationInfoDTO.getEndUserName());
        AccessTokenDO accessTokenDO = new AccessTokenDO(apiKeyValidationInfoDTO.getConsumerKey(), user, scopes, null,
                                                        null, apiKeyValidationInfoDTO.getValidityPeriod(), apiKeyValidationInfoDTO.getValidityPeriod(),
                                                        apiKeyValidationInfoDTO.getType());

        accessTokenDO.setAccessToken(validationContext.getAccessToken());

        String actualVersion = validationContext.getVersion();
        //Check if the api version has been prefixed with _default_
        if (actualVersion != null && actualVersion.startsWith(APIConstants.DEFAULT_VERSION_PREFIX)) {
            //Remove the prefix from the version.
            actualVersion = actualVersion.split(APIConstants.DEFAULT_VERSION_PREFIX)[1];
        }
        String resource = validationContext.getContext() + "/" + actualVersion + validationContext
                .getMatchingResource()
                          + ":" +
                          validationContext.getHttpVerb();

        try {
            if(scopeValidator != null){
                if(scopeValidator.validateScope(accessTokenDO, resource)){
                    return true;
                }   else {
                    apiKeyValidationInfoDTO.setAuthorized(false);
                    apiKeyValidationInfoDTO.setValidationStatus(APIConstants.KeyValidationStatus.INVALID_SCOPE);
                }
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("ERROR while validating token scope " + e.getMessage());
            apiKeyValidationInfoDTO.setAuthorized(false);
            apiKeyValidationInfoDTO.setValidationStatus(APIConstants.KeyValidationStatus.INVALID_SCOPE);
        }

        return false;
    }
}
