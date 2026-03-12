package com.revature.generator.dtos;
import lombok.Data;

@Data
public class PasswordGenerateRequest {

    private int length = 12;

    private boolean uppercase = true;
    private boolean lowercase = true;
    private boolean numbers = true;
    private boolean symbols = true;

    private boolean excludeSimilar = false;

    private int count = 1;
}
