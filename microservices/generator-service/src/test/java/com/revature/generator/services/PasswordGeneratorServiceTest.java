package com.revature.generator.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PasswordGeneratorServiceTest {

    private PasswordGeneratorService service;

    @BeforeEach
    void setUp() {
        service = new PasswordGeneratorService();
    }

    @Test
    void generatePassword_ShouldHaveCorrectLength() {
        int length = 16;
        String password = service.generatePassword(length, true, true, true, true);
        assertEquals(length, password.length());
    }

    @Test
    void generatePassword_ShouldIncludeUpperCase_WhenRequested() {
        String password = service.generatePassword(100, true, false, false, false);
        assertTrue(password.matches(".*[A-Z].*"));
        assertFalse(password.matches(".*[a-z].*"));
        assertFalse(password.matches(".*[0-9].*"));
    }

    @Test
    void generatePassword_ShouldIncludeSymbols_WhenRequested() {
        String password = service.generatePassword(100, false, false, false, true);
        assertTrue(password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\",.<>/?].*"));
    }
}
