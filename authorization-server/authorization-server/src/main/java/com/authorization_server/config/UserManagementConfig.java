package com.authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserManagementConfig {

	@Bean
	public UserDetailsService userDetailsService() {

		UserDetails userDetails = User.withUsername("ranjay@gmail.com").password("password")
				.authorities("read", "write").build();
		return new InMemoryUserDetailsManager(userDetails);
	}

}
