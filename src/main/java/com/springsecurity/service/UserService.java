package com.springsecurity.service;

import com.springsecurity.repository.UserAccountRepository;
import com.springsecurity.user.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserAccountRepository userRepository;
    private final PasswordEncoder encoder;



    public String saveUser(String role) {
        UserAccount user = UserAccount.builder()
                .username("user_"+role)
                .password(encoder.encode("1234"))
                .role("ROLE_"+role.toUpperCase())
                .enabled(true)
                .build();

        userRepository.save(user);

        return user.getUsername();
    }
}
