package com.security.securityDemo;

import com.security.securityDemo.model.User;
import com.security.securityDemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityDemoApplication {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	CommandLineRunner run(UserRepository userRepository) {
		return args -> {
			userRepository.save(new User(null, "user1", passwordEncoder.encode("12345"), "USER"));
			userRepository.save(new User(null, "admin", passwordEncoder.encode("Admin12345"), "ADMIN"));
		};
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurityDemoApplication.class, args);
	}

}
