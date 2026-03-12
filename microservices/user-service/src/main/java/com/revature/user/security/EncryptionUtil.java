package com.revature.user.security;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class EncryptionUtil {

    private final String SECRET = "1234567890123456";

    public String encrypt(String data) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key =
                new SecretKeySpec(SECRET.getBytes(), "AES");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return Base64.getEncoder()
                .encodeToString(cipher.doFinal(data.getBytes()));
    }

    public String decrypt(String encrypted) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key =
                new SecretKeySpec(SECRET.getBytes(), "AES");

        cipher.init(Cipher.DECRYPT_MODE, key);

        return new String(
                cipher.doFinal(Base64.getDecoder().decode(encrypted))
        );
    }
}

