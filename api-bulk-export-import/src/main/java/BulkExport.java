
import com.google.common.io.ByteStreams;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.ContentBody;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Properties;
import org.apache.commons.codec.binary.Base64;


public class BulkExport {
    static final String TRUST_STORE_URL_PROPERTY ="trust.store.url";
    static final String TRUST_STORE_PASSWORD_PROPERTY ="trust.store.password";
    static final String PUBLISHER_API_VERSION_PROPERTY ="publisher.api.version";
    static final String EXPORT_API_HOST ="export.api.host";
    static final String EXPORT_API_PORT ="export.api.port";

    static final String IMPORT_API_HOST = "import.api.host";
    static final String IMPORT_API_PORT = "import.api.port";

    static final String EXPORT_FOLDER_PROPERTY ="export.path";
    static final String ADMIN_USERID_PROPOERTY ="admin.userid";
    static final String ADMIN_PASSWORD_PROPERTY ="admin.password";
    static final String EXPORT_API_VERSION_PROPERTY="export.import.api.version";
    static final String HTTP_GET = "GET";
    static final String AUTHORIZATION_HTTP_HEADER ="Authorization";
    static final String BASIC_KEY ="Basic";
    static final String BEARER_KEY = "Bearer";
    static final String BEARER_TOKEN = "bearer.token";
    static final String ZIP_KEY =".zip";
    static final String API_NAME_KEY ="name";
    static final String API_VERSION_KEY ="version";
    static final String API_PROVIDER_KEY ="provider";
    static final String LIST_KEY ="list";
    static Properties prop;


    public static void main (String[] args){
        readProperties();
        try {
            //SSL Cert
            String trustStore = prop.getProperty(TRUST_STORE_URL_PROPERTY);
            String trustStorePassword = prop.getProperty(TRUST_STORE_PASSWORD_PROPERTY);
            if(trustStore != null && !trustStore.isEmpty() && trustStorePassword != null && !trustStorePassword.isEmpty()) {
                System.setProperty("javax.net.ssl.trustStore", trustStore);
                System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
            }

            //HTTP_GET API List from Publisher API

            String publisherAPI = "https://" + prop.getProperty(EXPORT_API_HOST) + ":" + prop.getProperty(EXPORT_API_PORT) +
                                  "/api/am/publisher/" + prop.getProperty(PUBLISHER_API_VERSION_PROPERTY) + "/apis";

            URL url = new URL(publisherAPI);
            HttpURLConnection conn = (HttpURLConnection)url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod(HTTP_GET);
            String authString = encodeCredentials (prop.getProperty(ADMIN_USERID_PROPOERTY), prop.getProperty(ADMIN_PASSWORD_PROPERTY));
            conn.setRequestProperty(AUTHORIZATION_HTTP_HEADER, BASIC_KEY + " " + authString);
            String responseStr = new String(ByteStreams.toByteArray(conn.getInputStream()));
            JSONParser parser = new JSONParser();
            try {
                JSONObject responseList = (JSONObject) parser.parse(responseStr);
                JSONArray apiList = (JSONArray) responseList.get(LIST_KEY);
                System.out.println("EXPORTING OUT " + apiList.size() + " APIs");

                for (Object api : apiList)  {
                    JSONObject jsonAPI =(JSONObject) api;
                    String apiProvider = (String)jsonAPI.get(API_PROVIDER_KEY);
                    String apiName = (String)jsonAPI.get(API_NAME_KEY);
                    String apiVersion = (String)jsonAPI.get(API_VERSION_KEY);
                    exportAPIAsZip(apiName, apiVersion, apiProvider);
                    importAPI(apiName);
                }

            } catch (ParseException error) {
                System.out.println("API List requested from API Manager is in wrong format" + error);
            }

        } catch (IOException error) {
            System.out.println("Error invoking Publisher API : " + error);
        }

    }


    private static void exportAPIAsZip(String apiName, String apiVersion, String apiProvider){
        try {

            /* // SSL communication
            String trustStore = prop.getProperty(TRUST_STORE_URL_PROPERTY);
            String trustStorePassword = prop.getProperty(TRUST_STORE_PASSWORD_PROPERTY);
            if(trustStore != null && !trustStore.isEmpty() && trustStorePassword != null && !trustStorePassword.isEmpty()) {
                System.setProperty("javax.net.ssl.trustStore", trustStore);
                System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
            }*/

            System.out.println("=================================================================");
            System.out.println("Exporting API [" + apiProvider + ":" + apiName + ":" + apiVersion + "] from "
                               + prop.getProperty(EXPORT_API_HOST) + ":" + prop.getProperty(EXPORT_API_PORT));

            String exportAPI = "https://" + prop.getProperty(EXPORT_API_HOST) + ":" + prop.getProperty(EXPORT_API_PORT)
                                  + "/api-import-export-" + prop.getProperty(EXPORT_API_VERSION_PROPERTY)
                                  + "/export-api?name=" + apiName + "&version=" + apiVersion + "&provider=" + apiProvider;
            // Exporting API
            URL url = new URL(exportAPI);
            HttpURLConnection conn = (HttpURLConnection)url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod(HTTP_GET);
            String authString = encodeCredentials (prop.getProperty(ADMIN_USERID_PROPOERTY), prop.getProperty(ADMIN_PASSWORD_PROPERTY));
            conn.setRequestProperty(AUTHORIZATION_HTTP_HEADER, BASIC_KEY + " " + authString);


            //Writing to file
            FileOutputStream fos = new FileOutputStream(prop.getProperty(EXPORT_FOLDER_PROPERTY) + File.separator + apiName + ZIP_KEY);
            fos.write(ByteStreams.toByteArray(conn.getInputStream()));
            fos.close();
        } catch (IOException error) {
            System.out.println("Error invoking API Export Service : " + error);
        }

    }

    private static void importAPI(String apiName) {

        System.out.println("Importing API [" + apiName + "] to " + prop.getProperty(IMPORT_API_HOST) + ":" + prop.getProperty(IMPORT_API_PORT));
        //curl -H "Authorization:Basic AbCdEfG" -F file=@"/Desktop/MyAPIFolder/myExportedAPI.zip" -k -X POST
        // "https://<host>:9443/api-import-export-<version>/import-api"
        String importAPI = "https://" + prop.getProperty(IMPORT_API_HOST) + ":" + prop.getProperty(IMPORT_API_PORT)
                              + "/api-import-export-" + prop.getProperty(EXPORT_API_VERSION_PROPERTY)
                              + "/import-api?preserveProvider=false";

        String authString = encodeCredentials (prop.getProperty(ADMIN_USERID_PROPOERTY), prop.getProperty(ADMIN_PASSWORD_PROPERTY));

        HttpClient httpclient = HttpClientBuilder.create().build();

        HttpPost httppost = new HttpPost(importAPI);
        httppost.setHeader(new BasicHeader(AUTHORIZATION_HTTP_HEADER, BASIC_KEY + " " + authString));
        File file = new File(prop.getProperty(EXPORT_FOLDER_PROPERTY) + File.separator + apiName + ZIP_KEY);

        MultipartEntityBuilder mpEntity = MultipartEntityBuilder.create();
        ContentBody cbFile = new FileBody(file);
        mpEntity.addPart("file", cbFile);

        HttpEntity httpEntity = mpEntity.build();
        httppost.setEntity(httpEntity);


        try {
            HttpResponse response = httpclient.execute(httppost);

            if (response.getStatusLine().getStatusCode() == 201)    {
                System.out.println("Import API " + apiName + " succeed! ");
                System.out.println("=================================================================");
            } else {
                System.out.println("Error Response received, status code : "+ response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            System.out.println("Error invoking API Export Service : "  + e);
        }

    }

    private static void readProperties(){
        prop = new Properties();
        InputStream input = null;
        try {

            input = new FileInputStream("config.properties");

            // load a properties file
            prop.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private static String encodeCredentials(String uid, String password){
        byte[] encodedBytes = Base64.encodeBase64((uid + ":" + password).getBytes());
        return new String(encodedBytes);

    }

}
