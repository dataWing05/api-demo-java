package com.example;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Main {

    private static final String URL = "http://127.0.0.1:8081/api/syncData/dataPush?resourceCode=847600820885";
    private static final String CLIENT_ID = "12805626";
    private static final String BUSINESS_ID = "253869086781";
    private static final String PUBLIC_KEY_PATH = "your_public_key_path.pem";

    private static final String MOCK_DATA = "[\n" +
            "    {\n" +
            "        \"operateType\": \"addOrUpdate\",\n" +
            "        \"operateTime\": \"2024-04-19 09:00:00\",\n" +
            "        \"value\": {\n" +
            "            \"RowGuid\": \"665132089930285056\",\n" +
            "            \"FaBaoGuid\": \"665132089930285056\",\n" +
            "            \"ProjectNo\": \"20240805JZ12\",\n" +
            "            \"ProjectName\": \"xxx\",\n" +
            "            \"FaBaoNo\": \"20240805JZ12\",\n" +
            "            \"FaBaoName\": \"xxx\",\n" +
            "            \"ZhaoBiaoType\": \"1\",\n" +
            "            \"ProjectType\": \"A\",\n" +
            "            \"CGUnitGuid\": \"4271c58ae53c481a63070d66e49d\",\n" +
            "            \"CGUnitName\": \"xx\",\n" +
            "            \"CGUnitOrgNum\": \"913301096767577672\",\n" +
            "            \"CGGroupName\": \"xx\",\n" +
            "            \"CGGroupOrgNum\": \"xx\",\n" +
            "            \"DLUnitGuid\": \"1234567890123456789012345678\",\n" +
            "            \"DLUnitName\": \"\",\n" +
            "            \"DLUnitOrgNum\": \"\",\n" +
            "            \"ZhaoBiaoFangShi\": \"G\",\n" +
            "            \"RegionCode\": \"330100\",\n" +
            "            \"PBMethod\": \"xx\",\n" +
            "            \"PlatformName\": \"xx\",\n" +
            "            \"PlatformCode\": \"113301007766375272\",\n" +
            "            \"CreateDate\": \"2024-11-29 17:05:51\"\n" +
            "        }\n" +
            "    }\n" +
            "]";

    public static void main(String[] args) {

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            String timeStamp = String.valueOf(System.currentTimeMillis());
            String nonce = String.valueOf(10000000 + (int)(Math.random() * 90000000));
            String publicKey = "your_sm2_public_key";
//            String sm2EncryptData = Sm2Utils.encryptSM2(PUBLIC_KEY_PATH, MOCK_DATA);
//            String sm2EncryptData = Sm2UtilsV2.encryptBase64(MOCK_DATA, publicKey);
            String sm2EncryptData = Sm2UtilsV3.encrypt(publicKey, MOCK_DATA);

            String signStr = sm2EncryptData + CLIENT_ID + BUSINESS_ID + timeStamp + nonce;
            String signature = sha256(signStr);

            HttpPost post = new HttpPost(URL);
            post.setHeader("X-Client-Id", CLIENT_ID);
            post.setHeader("X-Business-Id", BUSINESS_ID);
            post.setHeader("X-TimeStamp", timeStamp);
            post.setHeader("X-Nonce", nonce);
            post.setHeader("X-Signature", signature);
            post.setHeader("Content-Type", "application/json");
            post.setEntity(new StringEntity(sm2EncryptData, StandardCharsets.UTF_8));
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    String result = EntityUtils.toString(entity);
                    System.out.println(result);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String sha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(hash).substring(0, 32);
    }
}
