package com.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {


    // 비밀번호 암호화 Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder(){
        // BCryptPasswordEncoder: 해시 기반 암호화, 복호화 불가능(보안에 안전)
        return new BCryptPasswordEncoder();
    }

    // 메모리 기반 사용자 저장소 Bean
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.withUsername("user")
                .password(encoder.encode("1234"))    // 비밀번호 암호화 필수
                .roles("USER")  // ROLE_USER
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("1234"))
                .roles("ADMIN") // ROLE_ADMIN
                .build();

        // InMemoryUserDetailsManager: 메모리에 사용자 저장
        return new InMemoryUserDetailsManager(user, admin);
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // URL별 접근 권한 설정
            .authorizeHttpRequests(auth -> auth
                    // H2 콘솔은 로그인 없이 허용
                    .requestMatchers(PathRequest.toH2Console()).permitAll()
                    .requestMatchers(   // requestMatchers(): 특정 경로에 대한 접근 권한 지정 
                            "/",
                            "/public/**",
                            "/css/**",
                            "/js/**",
                            "/images/**").permitAll()   // permitAll(): 인증 없이 누구나 접근 가능
                    .requestMatchers("/admin/**").hasRole("ADMIN")  // ROLE_ADMIN 필요
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
            .csrf(csrf -> csrf.disable())
            .headers(headers -> headers
                    .frameOptions(frame -> frame.sameOrigin()));
        
        return http.build();    // 설정된 SecurityFilterChain 객체 반환
    }
}
