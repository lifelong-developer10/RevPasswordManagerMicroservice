package com.revature.vault.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptionUtilTest {

    private EncryptionUtil encryptionUtil;

    @BeforeEach
    void setUp() {
        encryptionUtil = new EncryptionUtil();
    }

    @Test
    void encryptAndDecrypt_ShouldReturnOriginalData() throws Exception {
        String originalData = "MySecretPassword123";
        String encrypted = encryptionUtil.encrypt(originalData);
        assertNotNull(encrypted);
        assertNotEquals(originalData, encrypted);

        String decrypted = encryptionUtil.decrypt(encrypted);
        assertEquals(originalData, decrypted);
    }

    @Test
    void encryptWithKey_ShouldUseProvidedKey() throws Exception {
        String originalData = "SensitiveInfo";
        String key = "CustomKey123456";
        String encrypted = encryptionUtil.encryptWithKey(originalData, key);
        
        String decrypted = encryptionUtil.decryptWithKey(encrypted, key);
        assertEquals(originalData, decrypted);
    }

    @Test
    void decryptWithWrongKey_ShouldThrowException() throws Exception {
        String originalData = "SomeData";
        String key1 = "KeyOne1234567890";
        String key2 = "KeyTwo1234567890";
        
        String encrypted = encryptionUtil.encryptWithKey(originalData, key1);
        
        assertThrows(Exception.class, () -> encryptionUtil.decryptWithKey(encrypted, key2));
    }
}
