package com.springsecurity.jwt;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private final JwtProperties props;
    private final SecretKey key;


    public JwtService(JwtProperties props) {
        this.props = props;
        this.key = Keys.hmacShaKeyFor(props.getSecret().getBytes(StandardCharsets.UTF_8));
    }



    // Access Token 발급(짧은 수명)
    public String generateAccessToken(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        Date now = new Date();
        Date exp = new Date(now.getTime() + props.getAccessTokenExpiry());

        return Jwts.builder()
                .setSubject(username)
                .setIssuer(props.getIssuer())
                .setIssuedAt(now)
                .setExpiration(exp)
                .claim("roles", roles)  // 권한 포함
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 발급(긴 수명, 보통 권한 불필요)
    public String generateRefreshToken(String username) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + props.getRefreshTokenExpiry());
        return Jwts.builder()
                .setSubject(username)
                .setIssuer(props.getIssuer())
                .setIssuedAt(now)
                .setExpiration(exp)
                .claim("typ", "refresh")
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰 파싱 및 클레임 추출
    public Jws<Claims> parseToken(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .requireIssuer(props.getIssuer())
                .build()
                .parseClaimsJws(token);
    }

    public List<String> getRoles(String token) {
        Object raw = parseToken(token).getBody().get("roles");
        if(raw instanceof List<?> list) {
            return list.stream().map(Object::toString).toList();
        }
        return List.of();
    }

    public boolean isExpired(String token) {
        Date exp = parseToken(token).getBody().getExpiration();
        return exp.before(new Date());
    }



}
