package org.wso2.carbon.apimgt.sciquest.subscription;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;
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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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

        if (validationContext == null || validationContext.getValidationInfoDTO() == null) {
            return false;
        }

        if (validationContext.isCacheHit()) {
            return true;
        }

        APIKeyValidationInfoDTO dto = validationContext.getValidationInfoDTO();


        if (validationContext.getTokenInfo() != null) {
            if (validationContext.getTokenInfo().isApplicationToken()) {
                dto.setUserType(APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION);
            } else {
                dto.setUserType("APPLICATION_USER");
            }

            AccessTokenInfo tokenInfo = validationContext.getTokenInfo();

            // This block checks if a Token of Application Type is trying to access a resource protected with
            // Application Token
            if (!hasTokenRequiredAuthLevel(validationContext.getRequiredAuthenticationLevel(), tokenInfo)) {
                dto.setAuthorized(false);
                dto.setValidationStatus(APIConstants.KeyValidationStatus.API_AUTH_INCORRECT_ACCESS_TOKEN_TYPE);
                return false;
            }
        }

        boolean state = false;

        try {
            if (log.isDebugEnabled()) {
                log.debug("Before validating subscriptions : " + dto);
                log.debug("Validation Info : { context : " + validationContext.getContext() + " , " +
                          "version : " + validationContext.getVersion() + " , consumerKey : " + dto.getConsumerKey() + " }");
            }

            state = validateSubscriptionDetails(validationContext.getContext(),
                                                validationContext.getVersion(),
                                                dto.getConsumerKey(), dto);
            if (state) {

                dto.setAuthorizedDomains(APIUtil.getListOfAuthorizedDomainsByConsumerKey(validationContext
                                                                                                 .getTokenInfo().getConsumerKey()));
                checkClientDomainAuthorized(dto, validationContext.getClientDomain());
            }


            if (log.isDebugEnabled()) {
                log.debug("After validating subscriptions : " + dto);
            }


        } catch (APIManagementException e) {
            log.error("Error Occurred while validating subscription.", e);
        }

        return state;
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

    private boolean validateSubscriptionDetails(String context, String version, String consumerKey,
                                               APIKeyValidationInfoDTO infoDTO) throws APIManagementException {

        String sql = "SELECT " +
                     "   APP.APPLICATION_ID," +
                     "   APP.NAME," +
                     "   APP.APPLICATION_TIER," +
                     "   AKM.KEY_TYPE" +
                     " FROM " +
                     "   AM_APPLICATION APP," +
                     "   AM_APPLICATION_KEY_MAPPING AKM" +
                     " WHERE " +
                     " AKM.CONSUMER_KEY = ? " +
                     "   AND AKM.APPLICATION_ID=APP.APPLICATION_ID";

        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            conn = APIMgtDBUtil.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, consumerKey);

            rs = ps.executeQuery();
            if (rs.next()) {
                infoDTO.setType(rs.getString("KEY_TYPE"));
                infoDTO.setApplicationId(rs.getString("APPLICATION_ID"));
                infoDTO.setApplicationName(rs.getString("NAME"));
                infoDTO.setApplicationTier(rs.getString("APPLICATION_TIER"));
                return true;
            }
            infoDTO.setAuthorized(false);
            infoDTO.setValidationStatus(APIConstants.KeyValidationStatus.API_AUTH_RESOURCE_FORBIDDEN);

        } catch (SQLException e) {
            log.error("Exception occurred while retrieving information from database ", e);
        }
        finally {
            APIMgtDBUtil.closeAllConnections(ps, conn, rs);
        }
        return false;
    }
}
