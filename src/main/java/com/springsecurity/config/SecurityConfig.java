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
            // URL별 접근 권한 설정
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(   // requestMatchers(): 특정 경로에 대한 접근 권한 지정 
                            "/",
                            "/public/**",
                            "/css/**",
                            "/js/**",
                            "/images/**").permitAll()   // permitAll(): 인증 없이 누구나 접근 가능
                    .anyRequest().authenticated()   // 그 외 모든 요청은 인증 필요
            )
            // 폼 로그인 설정
            .formLogin(form -> form
                    .loginPage("/login")    // loginPage(): 커스텀 로그인 페이지 경로 지정
                    .permitAll()    // permitAll(): 로그인 페이지 접근은 인증 없이 허용
            )
            // 로그아웃 설정
            .logout(logout -> logout
                    .logoutUrl("/logout")   // logoutUrl(): 로그아웃 요청 URL 지정
                    .permitAll()    // permitAll(): 로그아웃 요청은 누구나 가능
            )
            // CSRF 설정
            // 기본적으로 CSRF가 활성화되어 POST/PUT/DELETE 요청 시 토큰 필요
            // 개발/테스트 단계에서는 편의상 비활성화
            .csrf(csrf -> csrf.disable());
        
        return http.build();    // 설정된 SecurityFilterChain 객체 반환
    }
}
