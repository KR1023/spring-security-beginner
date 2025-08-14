package com.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")   // ROLE_ADMIN 필요
    @GetMapping("/admin/data")
    public String adminData() {
        return "관리자 전용 데이터";
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @GetMapping("/admin/manager/data")
    public String adminManagerData() {
        return "관리자 또는 매니저 데이터";
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping("/api/data")
    public String apiData() {
        return "API 전용 데이터";
    }
}
