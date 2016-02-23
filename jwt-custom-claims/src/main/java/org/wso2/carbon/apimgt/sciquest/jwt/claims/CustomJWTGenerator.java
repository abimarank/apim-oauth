package org.wso2.carbon.apimgt.sciquest.jwt.claims;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.token.AbstractJWTGenerator;
import org.wso2.carbon.apimgt.impl.token.ClaimsRetriever;
import org.wso2.carbon.apimgt.impl.token.JWTGenerator;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import java.util.Calendar;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;


public class CustomJWTGenerator extends AbstractJWTGenerator {
    private static final Log log = LogFactory.getLog(CustomJWTGenerator.class);
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

    @Override
    public String buildBody(APIKeyValidationInfoDTO keyValidationInfoDTO, String apiContext, String version,
                            String accessToken) throws APIManagementException {
        Map<String, String> standardClaims = populateStandardClaims(keyValidationInfoDTO, apiContext, version);

        if (standardClaims != null) {

            StringBuilder body = new StringBuilder();
            body.append("{");

            Iterator<Map.Entry<String, String>> entryIterator = standardClaims.entrySet().iterator();
            while (entryIterator.hasNext()) {
                Map.Entry<String, String> entry = entryIterator.next();
                String key = entry.getKey();
                if("exp".equals(key) || "nbf".equals(key) || "iat".equals(key)){
                    //These values should be numbers.
                    body.append("\"" + key + "\":" + entry.getValue() + ",");
                } else if ("http://wso2.org/claims/enduser".equals(key))  { // Since enduser is a JSON object
                    body.append("\"" + key + "\":" + entry.getValue() + ",");
                } else{
                    body.append("\"" + key + "\":\"" + entry.getValue() + "\",");
                }

            }

            if (body.length() > 1) {
                body.delete(body.length() - 1, body.length());
            }

            body.append("}");
            return body.toString();

        }

        return null;
    }
}
