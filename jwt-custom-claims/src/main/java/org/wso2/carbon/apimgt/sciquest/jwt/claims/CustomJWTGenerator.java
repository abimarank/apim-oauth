package org.wso2.carbon.apimgt.sciquest.jwt.claims;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.token.AbstractJWTGenerator;
import org.wso2.carbon.apimgt.impl.token.ClaimsRetriever;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.Map;


public class CustomJWTGenerator extends AbstractJWTGenerator {
    @Override
    public Map<String, String> populateStandardClaims(APIKeyValidationInfoDTO keyValidationInfoDTO, String apiContext,
                                                      String version) throws APIManagementException {
        //generating expiring timestamp
        long currentTime = Calendar.getInstance().getTimeInMillis();
        long expireIn = currentTime + 1000 * 60 * getTTL();

        //String jwtBody = "";
        String dialect;
        ClaimsRetriever claimsRetriever = getClaimsRetriever();
        if (claimsRetriever != null) {
            //jwtBody = JWT_INITIAL_BODY.replaceAll("\\[0\\]", claimsRetriever.getDialectURI(endUserName));
            dialect = claimsRetriever.getDialectURI(keyValidationInfoDTO.getEndUserName());
        } else {
            //jwtBody = JWT_INITIAL_BODY.replaceAll("\\[0\\]", dialectURI);
            dialect = getDialectURI();
        }

        String subscriber = keyValidationInfoDTO.getSubscriber();
        String applicationName = keyValidationInfoDTO.getApplicationName();
        String applicationId = keyValidationInfoDTO.getApplicationId();
        String tier = keyValidationInfoDTO.getTier();
        String endUserName = keyValidationInfoDTO.getEndUserName();
        String keyType = keyValidationInfoDTO.getType();
        String userType = keyValidationInfoDTO.getUserType();
        String applicationTier = keyValidationInfoDTO.getApplicationTier();
        String enduserTenantId = String.valueOf(APIUtil.getTenantId(endUserName));

        Map<String, String> claims = new LinkedHashMap<String, String>(20);

        claims.put("iss", API_GATEWAY_ID);
        claims.put("exp", String.valueOf(expireIn));
        claims.put(dialect + "/subscriber", subscriber);
        claims.put(dialect + "/applicationid", applicationId);
        claims.put(dialect + "/applicationname", applicationName);
        claims.put(dialect + "/applicationtier", applicationTier);
        claims.put(dialect + "/apicontext", apiContext);
        claims.put(dialect + "/version", version);
        claims.put(dialect + "/tier", tier);
        claims.put(dialect + "/keytype", keyType);
        claims.put(dialect + "/usertype", userType);
        claims.put(dialect + "/enduser", endUserName);
        claims.put(dialect + "/enduserTenantId", enduserTenantId);

        return claims;
    }

    @Override
    public Map<String, String> populateCustomClaims(APIKeyValidationInfoDTO keyValidationInfoDTO, String apiContext,
                                                    String version, String accessToken) throws APIManagementException {
        return null;
    }
}
