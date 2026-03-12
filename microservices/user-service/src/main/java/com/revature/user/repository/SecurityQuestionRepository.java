package com.revature.user.repository;

import com.revature.user.models.MasterUser;
import com.revature.user.models.SecurityQuestions;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SecurityQuestionRepository extends JpaRepository<SecurityQuestions,Long> {
    List<SecurityQuestions> findByUser(MasterUser user);
    void deleteByUser(MasterUser user);
}


