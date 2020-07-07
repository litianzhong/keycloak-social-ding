import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.broker.provider.util.SimpleHttp;

public class Test {
    public static String appid= "11111";
    public static String secret = "11111";
    public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        String PROFILE_URL = "https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=APPID" +
            "&timestamp=CURRENT_TIME&signature=CODE_CERT";
        String currentTime = String.valueOf(System.currentTimeMillis());
        String sigure = genSignature(currentTime);
        String url = PROFILE_URL.replace("APPID", appid).replace("CURRENT_TIME", currentTime)
            .replace("CODE_CERT", sigure);
        Map<String, String> map = new HashMap<>();
        map.put("tmp_auth_code","6579e7ec36f53b8b8a031396ec462e82");
        JsonNode json = SimpleHttp.doPost(url, HttpClientBuilder.create().build()).json(map).asJson();
        System.out.println(json);
    }

    private static String genSignature(String currentTime) throws NoSuchAlgorithmException,
        UnsupportedEncodingException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));
        byte[] signatureBytes = mac.doFinal(currentTime.getBytes("UTF-8"));
        return urlEncode(Base64.getEncoder().encodeToString(signatureBytes), "UTF-8");
    }

    private static String urlEncode(String value, String encoding) {
        if (value == null) {
            return "";
        }
        try {
            String encoded = URLEncoder.encode(value, encoding);
            return encoded.replace("+", "%20").replace("*", "%2A")
                .replace("~", "%7E").replace("/", "%2F");
        } catch ( UnsupportedEncodingException e ) {
            throw new IllegalArgumentException("FailedToEncodeUri", e);
        }
    }

}
