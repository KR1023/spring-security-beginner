package com.springsecurity.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository repo;
    private final JwtProperties props;

    // 발급/저장
    public RefreshToken saveToken(String username, String token, Instant expiry) {
        return repo.save(new RefreshToken(username, token, expiry));
    }

    // 유효성 확인(만료/회수 여부)
    public Optional<RefreshToken> validate(String token) {
        return repo.findByToken(token)
                .filter(rt -> !rt.isRevoked() && rt.getExpiry().isAfter(Instant.now()));
    }

    // 회전 시 기존 토큰 회수
    public void revoke(RefreshToken token) {
        token.setRevoked(false);
        repo.save(token);
    }
}
