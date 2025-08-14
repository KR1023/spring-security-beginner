package com.springsecurity.util;

import com.springsecurity.repository.UserAccountRepository;
import com.springsecurity.user.UserAccount;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class TestUserInitializer implements CommandLineRunner {

    private final UserAccountRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public TestUserInitializer(UserAccountRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }


    @Override
    public void run(String... args) throws Exception {
        if(userRepository.findByUsername("admin").isEmpty()) {
            UserAccount admin = UserAccount.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("1234"))
                    .role("ROLE_ADMIN")
                    .enabled(true)
                    .build();

            userRepository.save(admin);
            System.out.println("테스트 계정(admin/1234) 생성 완료");
        }
    }
}
