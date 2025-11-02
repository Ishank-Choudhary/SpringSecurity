package com.security.securityDemo.basicauth.config;

import com.security.securityDemo.basicauth.config.service.CustomUserDetailsService;
import com.security.securityDemo.jwt.config.AuthEntryPointJwt;
import com.security.securityDemo.jwt.config.AuthTokenFilter;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
//  This is your service that fetches users from the database.
//  It replaces the hardcoded in-memory users.
    private CustomUserDetailsService customUserDetailsService;
    @Autowired
    private AuthEntryPointJwt unAuthorizedHandler;
    @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    }

//  This is where you tell Spring Security “Which URLs need what permissions?”
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
//             Disable CSRF for simplicity (especially for H2 console)
               .csrf(csrf -> csrf.disable())
//          👇 This tells Spring Security to use our custom AuthEntryPointJwt class
//             whenever an unauthorized request (e.g. invalid/missing token) is made.
//             It replaces Spring's default error response with our own JSON format.
               .exceptionHandling(exception ->
                       exception.authenticationEntryPoint(unAuthorizedHandler))
//             Authorize requests
               .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/h2-console/**").permitAll() // allow H2 console
                       .requestMatchers("/api/auth/**").permitAll()
                       .requestMatchers("/user").hasRole("USER")
                       .requestMatchers("/admin").hasRole("ADMIN")
                       .anyRequest().authenticated()
               )

//             By default, Spring Security blocks all pages that try to load inside frames — to protect against clickjacking attacks.
//             So when you open
//             👉 http://localhost:8080/h2-console
//             the browser tries to load the H2 console web interface inside a frame.
               .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

//              Enable HTTP Basic auth with default behavior, no extra customization
//              .httpBasic(Customizer.withDefaults())

//              Disable session creation (optional for stateless APIs)
               .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS));

//     ✅ Add JWT filter before Spring’s UsernamePasswordAuthenticationFilter
       http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);

       return http.build();
   }


//  password encoder bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//  “Whenever someone tries to log in, verify their credentials using my customUserDetailsService,
//   and check the password using BCryptPasswordEncoder.”

//  Expose AuthenticationManager as a Bean so we can inject it in our controller.
//  It retrieves the internally configured AuthenticationManager from Spring’s AuthenticationConfiguration.
//  Without this, we can’t call authenticationManager.authenticate(...) in our custom login endpoint.

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

}
