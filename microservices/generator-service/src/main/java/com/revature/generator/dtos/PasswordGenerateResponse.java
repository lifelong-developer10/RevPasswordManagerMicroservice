package com.revature.generator.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class PasswordGenerateResponse {

    private List<String> passwords;

}
