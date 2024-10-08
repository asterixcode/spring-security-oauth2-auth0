package com.example.auth0.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

  @GetMapping("/")
  public String home() {
    return "index";
  }

  @GetMapping("/profile")
  public String profile(Model model, @AuthenticationPrincipal OidcUser user) {

    model.addAttribute("profile", user.getClaims());

    return "profile";
  }
}
