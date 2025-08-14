package com.springsecurity.auth;

import com.springsecurity.jwt.JwtProperties;
import com.springsecurity.jwt.JwtService;
import com.springsecurity.jwt.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final JwtProperties props;

    // 로그인: username/password -> Access + Refresh 발급
    @PostMapping("/login")
    public ResponseEntity<AuthDto.TokenResponse> login(@RequestBody AuthDto.LoginRequest req) {
        Authentication auth  =  authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username, req.password)
        );

        String access = jwtService.generateAccessToken(auth);
        String refresh = jwtService.generateRefreshToken(auth.getName());

        // Refresh 저장(회전/폐기 관리)
        var claims = jwtService.parseToken(refresh).getBody();
        refreshTokenService.saveToken(auth.getName(), refresh, claims.getExpiration().toInstant());

        return ResponseEntity.ok(new AuthDto.TokenResponse(access, refresh));
    }

    // 리프레시: 유효한 refresh로 새 Access 발급(+ 회전)
    @PostMapping("/refresh")
    public ResponseEntity<AuthDto.TokenResponse> refresh(@RequestBody AuthDto.RefreshRequest req) {
        var opt = refreshTokenService.validate(req.refreshToken);
        if(opt.isEmpty())
            return ResponseEntity.status(401).build();

        var stored = opt.get();
        var claims = jwtService.parseToken(stored.getToken()).getBody();
        String username = claims.getSubject();

        // 기존 refresh 회수
        refreshTokenService.revoke(stored);

        // 새 토큰들 발급(회전)
        var auth = new UsernamePasswordAuthenticationToken(username, null, null);
        String newAccess = jwtService.generateAccessToken(auth);
        String newRefresh = jwtService.generateRefreshToken(username);

        var newClaims = jwtService.parseToken(newRefresh).getBody();
        refreshTokenService.saveToken(username, newRefresh, newClaims.getExpiration().toInstant());

        return ResponseEntity.ok(new AuthDto.TokenResponse(newAccess, newRefresh));
    }
}
