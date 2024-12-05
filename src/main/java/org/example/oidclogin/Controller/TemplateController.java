package org.example.oidclogin.Controller;

import org.example.oidclogin.Service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TemplateController {

    @Autowired
    private OAuth2UserService oAuth2UserService;

    @GetMapping("/")
    public String home() {
        return "loginpage";
    }

    @GetMapping("/welcome")
    public String welcome(Model model, Authentication authentication) {
        String name = "Guest";
        String email = "Not Available";

        if (authentication != null) {
            if (authentication.getPrincipal() instanceof UserDetails) {
                // Username/Password authentication
                UserDetails userDetails = (UserDetails) authentication.getPrincipal();
                name = userDetails.getUsername(); // Use username
            } else if (authentication.getPrincipal() instanceof OAuth2User) {
                // OAuth2 authentication
                OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                name = (String) oauth2User.getAttributes().get("name"); // Get the name
                email = (String) oauth2User.getAttributes().get("email"); // Get the email
                if(email == null){
                    email = oAuth2UserService.fetchEmail(oauth2User,"github");
                }
            }
        }

        model.addAttribute("name", name);
        model.addAttribute("email", email);
        return "welcome";
    }
}
