package com.springsecurity.auth;

import jakarta.validation.constraints.NotBlank;

public class AuthDto {
    // 로그인 요청 DTO
    public static class LoginRequest {
        @NotBlank public String username;
        @NotBlank public String password;
    }

    // 로그인 / 리프레시 응답 DTO
    public static class TokenResponse {
        public String accessToken;
        public String refreshToken;
        public TokenResponse(String a, String r) {
            this.accessToken = a;
            this.refreshToken = r;
        }
    }

    // 리프레시 요청 DTO
    public static class RefreshRequest {
        @NotBlank public String refreshToken;
    }
}
