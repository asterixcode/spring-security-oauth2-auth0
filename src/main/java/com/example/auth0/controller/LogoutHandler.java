package com.example.auth0.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class LogoutHandler extends SecurityContextLogoutHandler {

  /**
   * ClientRegistrationRepository will be used to look up information about
   * the configured provider to call auth0 logout endpoint.
   */
  private final ClientRegistrationRepository clientRegistrationRepository;

  public LogoutHandler(ClientRegistrationRepository clientRegistrationRepository) {
    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  @Override
  public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    super.logout(request, response, authentication);

    // Build the url to log the user out of Auth0 and redirect them to the homepage
    // URL will look like https://YOUR_DOMAIN/v2/logout?client_id=YOUR_CLIENT_ID&returnTo=http://localhost:8080
    String issuer = clientRegistrationRepository.findByRegistrationId("auth0")
            .getProviderDetails()
            .getConfigurationMetadata()
            .get("issuer").toString();

    String clientId = clientRegistrationRepository.findByRegistrationId("auth0")
            .getClientId();

    String returnTo = ServletUriComponentsBuilder.fromCurrentContextPath().build().toString();

    String logoutUrl = UriComponentsBuilder
            .fromHttpUrl(issuer + "v2/logout")
            .queryParam("client_id", clientId)
            .queryParam("returnTo", returnTo)
            .encode()
            .buildAndExpand(clientId, returnTo)
            .toUriString();

    try {
      response.sendRedirect(logoutUrl);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
