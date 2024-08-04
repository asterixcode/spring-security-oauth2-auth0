package com.example.auth0.config;

import com.example.auth0.controller.LogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final LogoutHandler logoutHandler;

  public SecurityConfig(LogoutHandler logoutHandler) {
    this.logoutHandler = logoutHandler;
  }

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(
            auth -> auth.requestMatchers("/").permitAll().anyRequest().authenticated())
        .logout(
            logout ->
                logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .addLogoutHandler(logoutHandler))
        .formLogin(Customizer.withDefaults())
        .oauth2Login(Customizer.withDefaults())
        .build();
  }
}
