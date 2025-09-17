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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Main {

    private static final String URL = "http://127.0.0.1:8081/api/data/load";
    private static final String CLIENT_ID = "12805626";
    private static final String BUSINESS_ID = "253869086781";
    private static final String PUBLIC_KEY_PATH = "public_key.pem";

    private static final String MOCK_DATA = "{\n" +
            "                \"upsert\": [\n" +
            "                    {\"id\": 1, \"name\": \"Alice\", \"score\": 30},\n" +
            "                    {\"id\": 2, \"name\": \"Bob\", \"score\": 25}\n" +
            "                ],\n" +
            "                \"delete\": [\n" +
            "                    {\"id\": 100, \"score\": 30},\n" +
            "                    {\"id\": 110, \"score\": 30}\n" +
            "                ]\n" +
            "            }";

    public static void main(String[] args) {


        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            String timeStamp = String.valueOf(System.currentTimeMillis());
            String nonce = String.valueOf(10000000 + (int)(Math.random() * 90000000));
            String sm2EncryptData = Sm2Utils.encryptSM2(PUBLIC_KEY_PATH, MOCK_DATA);

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
