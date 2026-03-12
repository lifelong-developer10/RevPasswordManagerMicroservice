package com.revature.vault.security;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class EncryptionUtil {

    private final String DEFAULT_SECRET = "1234567890123456";

    public String encrypt(String data) throws Exception {
        return encryptWithKey(data, DEFAULT_SECRET);
    }

    public String decrypt(String encrypted) throws Exception {
        return decryptWithKey(encrypted, DEFAULT_SECRET);
    }

    public String encryptWithKey(String data, String secretKey) throws Exception {
        byte[] keyBytes = deriveKey(secretKey);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }

    public String decryptWithKey(String encrypted, String secretKey) throws Exception {
        byte[] keyBytes = deriveKey(secretKey);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
    }

    private byte[] deriveKey(String password) throws Exception {
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes("UTF-8"));
        return java.util.Arrays.copyOf(key, 16); // Use first 128 bits
    }
}
