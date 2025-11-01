package com.security.securityDemo.basicauth.config.controller;

import com.security.securityDemo.jwt.config.LoginRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;


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

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try{

        }catch (AuthenticationException exception){
            Map<String, Object> map = new HashMap<>();
            map.put("message","Bad")
        }
    }
}
