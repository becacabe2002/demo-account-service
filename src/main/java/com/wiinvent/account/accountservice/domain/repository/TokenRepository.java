package com.wiinvent.account.accountservice.domain.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.wiinvent.account.accountservice.domain.models.Token;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    // since Entity names are "token" and "user"
    @Query("""
    select t from token t inner join user u on t.user.id = u.id
    where u.id = :userID and (t.expired = false or t.revoked = false)
    """)
    List<Token> findAllTokensByUser(Integer userID);

    Optional<Token> findByToken(String token);
}
