package com.springsecurity.config;

import com.springsecurity.auth.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
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
@EnableMethodSecurity   // 메서드 보안 활성화
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;

    // 비밀번호 암호화 Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder(){
        // BCryptPasswordEncoder: 해시 기반 암호화, 복호화 불가능(보안에 안전)
        return new BCryptPasswordEncoder();
    }

    // DB 기반 인증 제공자 등록
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(encoder);

        return provider;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, DaoAuthenticationProvider authProvider) throws Exception {
        http
            .authenticationProvider(authProvider)   // DB 인증 제공자 적용
            .authorizeHttpRequests(auth -> auth // URL별 접근 권한 설정
                    // H2 콘솔은 로그인 없이 허용
                    .requestMatchers(PathRequest.toH2Console()).permitAll()
                    .requestMatchers(   // requestMatchers(): 특정 경로에 대한 접근 권한 지정 
                            "/",
                            "/public/**",
                            "/css/**",
                            "/js/**",
                            "/images/**").permitAll()   // permitAll(): 인증 없이 누구나 접근 가능
                    .requestMatchers("/admin/**").hasRole("ADMIN")  // ROLE_ADMIN 필요
                    .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")  // ROLE_ADMIN 또는 ROLE_MANAGER
                    .requestMatchers("/api/**").hasAnyAuthority("ROLE_API", "ROLE_ADMIN")    // ROLE_접두사까지 명시
                    .anyRequest().authenticated()   // 그 외 모든 요청은 인증 필요
            )
            // 폼 로그인 설정
            .formLogin(form -> form
                    .loginPage("/login")    // loginPage(): 커스텀 로그인 페이지 경로 지정
                    .defaultSuccessUrl("/", true)   // 로그인 성공 후 이동할 페이지
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
