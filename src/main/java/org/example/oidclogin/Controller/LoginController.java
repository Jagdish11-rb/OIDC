package org.example.oidclogin.Controller;

import lombok.extern.slf4j.Slf4j;
import org.example.oidclogin.Service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@Slf4j
public class LoginController {


    @Autowired
    private OAuth2UserService oAuth2UserService;

    @GetMapping("/user")
    public Map<String, Object> user(OAuth2AuthenticationToken authentication) {
        System.out.println(authentication);
        return authentication.getPrincipal().getAttributes();
    }

    @GetMapping("/dashboard")
    public Map<String, Object> dashboard(@AuthenticationPrincipal OAuth2User principal) {
        System.out.println(principal);
        return principal.getAttributes();
    }

    @GetMapping("/email")
    public String getEmail() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {

            if (auth instanceof UsernamePasswordAuthenticationToken) {
                Object principal = auth.getPrincipal();
                if (principal instanceof UserDetails) {
                    UserDetails userDetails = (UserDetails) principal;
                    log.info("User {} logged in successfully via {}", userDetails.getUsername(), "basic authentication process");
                    return "Authenticated user name : " + userDetails.getUsername();
                }
            }

            if (auth instanceof OAuth2AuthenticationToken) {

                OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) auth;
                OAuth2User oAuth2User = authentication.getPrincipal();
                String registrationId = authentication.getAuthorizedClientRegistrationId();
                String email = oAuth2UserService.fetchEmail(oAuth2User, registrationId);

                if (email != null) {
                    log.info("User {} logged in successfully via {}", email, registrationId);
                    return "Authenticated user email : " + email;
                } else {
                    return "Email not found for user.";
                }
            }
        }
        return "Unauthenticated user.";
    }


}
