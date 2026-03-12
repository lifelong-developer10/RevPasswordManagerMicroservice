package com.revature.user.services;

import com.revature.user.dtos.UserQuestionAnswer;
import com.revature.user.models.MasterUser;
import com.revature.user.models.SecurityQuestionMaster;
import com.revature.user.models.SecurityQuestions;
import com.revature.user.repository.SecurityQuestionMasterRepository;
import com.revature.user.repository.SecurityQuestionRepository;
import com.revature.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional
public class SecurityQuestionService {

    private final SecurityQuestionRepository questionRepo;
    private final SecurityQuestionMasterRepository masterRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;
    @Transactional
    public Map<String, String> updateQuestions(String username,
                                               List<UserQuestionAnswer> list){

        MasterUser user =
                userRepo.findByUsername(username)
                        .orElseThrow();

        // delete old questions
        questionRepo.deleteByUser(user);

        for (UserQuestionAnswer q : list) {

            SecurityQuestionMaster master =
                    masterRepo.findById(q.getQuestionId())
                            .orElseThrow();

            SecurityQuestions entity = new SecurityQuestions();

            entity.setUser(user);
            entity.setQuestion(master);
            entity.setAnswerHash(
                    encoder.encode(
                            q.getAnswer().toLowerCase().trim()
                    )
            );
            questionRepo.save(entity);
        }

        return Map.of("message", "Security Questions Updated");
    }

    public List<SecurityQuestions> getUserQuestions(String username) {

        MasterUser user =
                userRepo.findByUsername(username)
                        .orElseThrow();

        return questionRepo.findByUser(user);
    }
}

