package com.wiinvent.account.accountservice.domain.repository;

import com.wiinvent.account.accountservice.domain.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Define methods for working with user data in DB
 * Provide an abstraction layer between application and DB,
 * so that we can perform CRUD operations without having to write SQL queries
 */
public interface UserRepository extends JpaRepository<User, Integer>{
    Optional<User> findByEmail(String email);
}
