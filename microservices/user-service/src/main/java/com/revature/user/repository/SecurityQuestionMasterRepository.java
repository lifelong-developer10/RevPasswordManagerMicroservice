package com.revature.user.repository;

import com.revature.user.models.MasterUser;
import com.revature.user.models.SecurityQuestionMaster;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityQuestionMasterRepository
        extends JpaRepository<SecurityQuestionMaster, Long> {

}

