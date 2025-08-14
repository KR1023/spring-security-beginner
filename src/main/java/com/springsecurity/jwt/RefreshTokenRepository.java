package com.springsecurity.jwt;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUsername(String username);  // (선택) 사용자 전체 무효화용

}
