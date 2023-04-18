package com.wiinvent.account.accountservice.domain.models;

import jakarta.persistence.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = "token")
@Table(name = "token")
public class Token {
    @Id
    @GeneratedValue
    private Integer id;

    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    private boolean expired;

    private boolean revoked;

    // Owning Entity
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
