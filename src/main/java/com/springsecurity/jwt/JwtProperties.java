package com.springsecurity.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
    private String issuer;  // 발급자
    private String secret;  // 비밀키
    private long accessTokenExpiry; // milliseconds
    private long refreshTokenExpiry; // milliseconds


}
