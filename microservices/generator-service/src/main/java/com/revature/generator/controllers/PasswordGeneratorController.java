package com.revature.generator.controllers;

import com.revature.generator.dtos.PasswordGenerateRequest;
import com.revature.generator.dtos.PasswordGenerateResponse;
import com.revature.generator.services.PasswordGeneratorService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/generator")
@RequiredArgsConstructor
public class PasswordGeneratorController {

    private final PasswordGeneratorService generatorService;

    @GetMapping("/generate")
    public PasswordGenerateResponse generate(
            @RequestParam(defaultValue = "12") int length) {

        PasswordGenerateRequest request = new PasswordGenerateRequest();
        request.setLength(length);
        request.setCount(1);
        request.setUppercase(true);
        request.setLowercase(true);
        request.setNumbers(true);
        request.setSymbols(true);

        List<String> passwords =
                generatorService.generatePasswords(request);

        return new PasswordGenerateResponse(passwords);
    }
}
