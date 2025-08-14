package com.springsecurity.jwt;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 50)
    private String username;
    
    @Column(nullable = false, unique = true, length = 512)
    private String token;   // JWT 문자열

    @Column(nullable = false)
    private Instant expiry;

    @Column(nullable = false)
    private boolean revoked = false;

    public RefreshToken() {}

    public RefreshToken(String username, String token, Instant expiry) {
        this.username = username;
        this.token = token;
        this.expiry = expiry;
    }
}
