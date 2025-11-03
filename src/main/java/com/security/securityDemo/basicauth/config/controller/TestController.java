package com.security.securityDemo.basicauth.config.controller;

import com.security.securityDemo.jwt.config.JwtUtil;
import com.security.securityDemo.jwt.config.LoginRequest;
import com.security.securityDemo.jwt.config.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
public class TestController {

    @Autowired
//  you’re asking Spring’s IoC (Inversion of Control) container to inject a bean that implements it which is - ProviderManager
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

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

//  this is the first place where username and password authentication happens.
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication; // in spring whenever a user is authenticated it will represent as an Authentication user
        try{
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

        }catch (AuthenticationException exception){
            Map<String, Object> map = new HashMap<>();
            map.put("message","Bad Credentials");
            map.put("status",false);

            return  new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }
//      SecurityContextHolder is like a storage box (per request) where Spring Security keeps information
//      about the currently logged-in user.
        SecurityContextHolder.getContext().setAuthentication(authentication);
//      UserDetails is an interface in Spring Security that represents —
//      ➡️ a single user’s information (username, password, roles, etc).
//      `getPrincipal()` returns the user details object (the one implementing UserDetails).
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//      We are generating a new JWT token using userDetails info from JwtUtil class
        String jwtToken = jwtUtil.generateTokenFromUsername(userDetails);
//      Extracting the roles (authorities) of this user.
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item-> item.getAuthority())
                .collect(Collectors.toList());
//      Preparing the response that includes username, token, and roles.
        LoginResponse response = new LoginResponse(jwtToken,userDetails.getUsername(),roles);
        return ResponseEntity.ok(response);
    }
}
