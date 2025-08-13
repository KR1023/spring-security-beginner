package com.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 모든 요청은 인증 필요
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()   // 모든 요청 인증 필요
                )
                // 기본 로그인 폼 사용
                .formLogin(form -> form
                        .permitAll()
                )
                // 로그아웃 설정
                .logout(logout -> logout
                        .permitAll()
                );

        return http.build();
    }
}
