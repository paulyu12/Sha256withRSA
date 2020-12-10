package com.demo;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class Demo {
    /**
     * 私钥签名
     */
    public static String sha256withRSASignature(String privateKeyStr, String dataStr) {
        try {
            byte[] key = Base64.getDecoder().decode(privateKeyStr);
            byte[] data = dataStr.getBytes();

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return new String(Base64.getEncoder().encode(signature.sign()));
        } catch (Exception e) {
            throw new RuntimeException("签名计算出现异常");
        }
    }

    public static void main (String[] args) {
        try {
            // Java 使用 PKCS# 8 格式的私钥，去掉 BEGIN 和 END.
            String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOUubn4qizJtpx+nyHOOfV+XbBPsC7aWblIS3Pqv7/DBJ+rkp9gfyrUA78L3YjASmmU1uupiY5dC7o/TuaDSVA4K8Tmx22YC8PZ7HfAJ5/yVaaB2HmpSjg4xyahLPcgCn/v8WcxqDUh6VJ92uic8EPFrOno1SZBkhOxgroKwSX97AgMBAAECgYEAmQx28X6L0rNzpiowLSt9Andmz68U62xuZBUAydDwlYEInU7x39zrTBFCDJuUULI7tVc6aggmpf8mvZoRHxsW0b5jHLqOwy7fKfAzBuFxWYJYKZmha4Tmll0QmTqU505rLtOQTjlf9Zzsr2Jmza64HuzKUi8r8dXHGK3oUZ49rhECQQD175WgBvEG/vwfLFFxK1b4pzeWYTjNgEYBvYhjHjxQQ3fic/msjxO6yqzLsJneu9IyLUKlWWPZ5AoVTwXNUXKPAkEA7o9T2ruKXw215x29gGQMSuUJrBJ4J2T2zv2F6VPQyuD1xZpVYU6fRTGBPnkw9dYZ0xFdRQ4I2cyKVrD+nt0qVQJAOmMZ67caK+YHZ0M3Rp3adQgF+26zdJ5agHlF0vpPqWKLKLkN8ni5X2RUp7sSnL2MhpsWMnlJamZoOmzbXMZUYwJBAIEe8rQhbfOk6B//6OHlRQIElgect4wbCbtfXWu9AfXNbTlXH39bnrlE4j9+ORHWoIOtkl4eCoxYOUhS5H34F0ECQAjz4laBYt1Zx5df0+67go2Ya6THgZnDafne8wqnQW6m5DEyidFZM36QDvpyrxAiPzG4QGR3HLU0VEwSQa7rvmY=";

            String src = "Hello, sha256 with rsa!";
            String apisign = sha256withRSASignature(privateKey, src);
            System.out.println(apisign);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}