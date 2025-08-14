package com.springsecurity.config;

import com.springsecurity.auth.CustomUserDetailsService;
import com.springsecurity.jwt.JwtAuthenticationFilter;
import com.springsecurity.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity   // 메서드 보안 활성화
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    // 비밀번호 암호화 Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder(){
        // BCryptPasswordEncoder: 해시 기반 암호화, 복호화 불가능(보안에 안전)
        return new BCryptPasswordEncoder();
    }

    // DB 기반 인증에 UserDetailsService + PasswordEncoder 사용
    @Bean
    public AuthenticationProvider authenticationProvider(PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(encoder);

        return provider;
    }
    
    // AuthenticationManager 주입(로그인 시 사용)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    
    // Stateless + JWT 필터 등록
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, DaoAuthenticationProvider authProvider) throws Exception {
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtService, userDetailsService);
        http
            .csrf(csrf -> csrf.disable()) // JWT 환경에서는 보통 stateless라 비활성화
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 미사용
            .authorizeHttpRequests(auth -> auth // URL별 접근 권한 설정
                    // H2 콘솔은 로그인 없이 허용
                    .requestMatchers(PathRequest.toH2Console()).permitAll()
                    .requestMatchers(   // requestMatchers(): 특정 경로에 대한 접근 권한 지정 
                            "/",
                            "/public/**",
                            "/css/**",
                            "/js/**",
                            "/images/**").permitAll()   // permitAll(): 인증 없이 누구나 접근 가능
                    .requestMatchers("/api/auth/**").permitAll() // 로그인/리프레시 허용
                    .requestMatchers("/admin/**").hasRole("ADMIN")  // ROLE_ADMIN 필요
                    .anyRequest().authenticated()   // 그 외 모든 요청은 인증 필요
            )
            // UsernamePasswordAuthenticationFilter 전에 JWT 검증 필터 실행
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .headers(headers -> headers
                    .frameOptions(frame -> frame.sameOrigin()));
        
        return http.build();    // 설정된 SecurityFilterChain 객체 반환
    }
}
