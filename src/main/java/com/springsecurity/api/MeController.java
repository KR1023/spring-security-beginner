package com.springsecurity.api;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {
    @GetMapping("/me")
    public Object me(@AuthenticationPrincipal UserDetails user) {
        return user == null ? "anonymous" : user.getUsername();
    }
}
