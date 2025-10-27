package com.security.securityDemo.basicauth.config;

import com.security.securityDemo.basicauth.config.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    //This is your service that fetches users from the database.
    //It replaces the hardcoded in-memory users.
    private CustomUserDetailsService customUserDetailsService;

   // This is where you tell Spring Security “Which URLs need what permissions?”
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
               // Disable CSRF for simplicity (especially for H2 console)
               .csrf(csrf -> csrf.disable())
               // Authorize requests
               .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/h2-console/**").permitAll() // allow H2 console
                       .requestMatchers("/user").hasRole("USER")
                       .requestMatchers("/admin").hasRole("ADMIN")
                       .anyRequest().authenticated()
               )

               //By default, Spring Security blocks all pages that try to load inside frames — to protect against clickjacking attacks.
               //So when you open
               //👉 http://localhost:8080/h2-console
               //the browser tries to load the H2 console web interface inside a frame.
               .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

               // Enable HTTP Basic auth with default behavior, no extra customization
               .httpBasic(Customizer.withDefaults())

               // Disable session creation (optional for stateless APIs)
               .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS));

       return http.build();
   }


    //password encoder bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //“Whenever someone tries to log in, verify their credentials using my customUserDetailsService,
    // and check the password using BCryptPasswordEncoder.”

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }



}
