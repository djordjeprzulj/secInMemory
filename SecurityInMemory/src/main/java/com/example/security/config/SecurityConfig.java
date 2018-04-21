package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	/*
	//	Basic authentication 
	//  autentifikacija za svaku stranicu, dozvoljen pristup samo home
	//	ne uzima se u obzir autorizacija
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests().antMatchers("/", "/home").permitAll()
			.anyRequest().authenticated()
			.and().httpBasic()	// login browsera
			.and().csrf().disable();
	}
	*/
	
	//	in memory autentifikacija
	//	default login forma
	// 	odjava na /login?logout
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/home","/","/public").permitAll()
				.antMatchers("/insert").hasRole("ADMIN")
				.anyRequest().authenticated()
				.and()
			.formLogin();
	}

	@Bean
	public UserDetailsService userDetailsService() {		
		UserDetails user1 = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();
		UserDetails user2 = User.withDefaultPasswordEncoder().username("admin").password("password").roles("ADMIN").build();
		return new InMemoryUserDetailsManager(user1, user2);
	}
}