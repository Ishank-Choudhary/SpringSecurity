package com.security.securityDemo.basicauth.config.service;

import com.security.securityDemo.basicauth.config.model.User;
import com.security.securityDemo.basicauth.config.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("user name not found!!!"));

        //All the getters used below are the ones that we are getting from our User entity class using Lombok library.
        UserBuilder builder = org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole());
        // builder then uses these values to create a new UserDetails object via:
        return builder.build();
    }
}
