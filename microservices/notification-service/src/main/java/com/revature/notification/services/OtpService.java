package com.revature.notification.services;

import com.revature.notification.models.OTPGenerater;
import com.revature.notification.repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepo;

    public String generateOtp(String username) {



        String code = String.valueOf(100000 +
                new Random().nextInt(900000));

        OTPGenerater otp = new OTPGenerater();

        otp.setCode(code);
        otp.setOwnerUsername(username);
        otp.setUsed(false);
        otp.setExpiryTime(LocalDateTime.now().plusMinutes(5));

        otpRepo.save(otp);


        System.out.println("OTP for " + username + " = " + code);

        return "OTP sent successfully";
    }

    public boolean verifyOtp(String username, String code) {



        OTPGenerater otp = otpRepo
                .findTopByOwnerUsernameOrderByExpiryTimeDesc(username)
                .orElseThrow();

        if (otp.isUsed())
            throw new RuntimeException("OTP already used");

        if (otp.getExpiryTime().isBefore(LocalDateTime.now()))
            throw new RuntimeException("OTP expired");

        if (!otp.getCode().equals(code))
            throw new RuntimeException("Invalid OTP");

        otp.setUsed(true);
        otpRepo.save(otp);

        return true;
    }
}
