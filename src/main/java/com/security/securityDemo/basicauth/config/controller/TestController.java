package com.security.securityDemo.basicauth.config.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userTesting(){
        return "Hello user !!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminTesting(){
        return "Hello Admin !!";
    }
}
