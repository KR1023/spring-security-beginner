package com.springsecurity.auth;

import com.springsecurity.user.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

// SpringSecurity에서 사용할 사용자 객체
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final UserAccount account; // DB 사용자 정보

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // DB role 값 그대로 사용(예: ROLE_USER)
        return List.of(new SimpleGrantedAuthority(account.getRole()));
    }

    @Override
    public String getPassword() {
        return account.getPassword();
    }

    @Override
    public String getUsername() {
        return account.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;    // 계정 만료 여부
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;    // 계정 잠금 여부
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;    // 비밀번호 만료 여부
    }

    @Override
    public boolean isEnabled() {
        return account.isEnabled(); // 계정 활성화 여부
    }
}
