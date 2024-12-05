package org.example.oidclogin.Service;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Service
public class OAuth2UserService {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public OAuth2UserService(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    public String fetchEmail(OAuth2User oAuth2User, String registrationId) {
        String email;
        if ("google".equals(registrationId)) {
            email = oAuth2User.getAttribute("email");
        } else if ("github".equals(registrationId)) {
            email = oAuth2User.getAttribute("email");
            if (email == null) {
                email = fetchPrimaryEmailFromGitHub(oAuth2User);
            }
        } else {
            return null;
        }
        return email;
    }

    private String fetchPrimaryEmailFromGitHub(OAuth2User user) {
        OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            String registrationId = authentication.getAuthorizedClientRegistrationId();
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(registrationId, authentication.getName());
            OAuth2AccessToken accessToken = client.getAccessToken();

            if (accessToken == null) {
                throw new IllegalStateException("No access token available for GitHub user");
            }

            // Call GitHub API to get email list
            RestTemplate restTemplate = new RestTemplate();
            String emailEndpoint = "https://api.github.com/user/emails";

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken.getTokenValue());
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                    emailEndpoint, HttpMethod.GET, entity,
                    new ParameterizedTypeReference<List<Map<String, Object>>>() {
                    });

            if (!response.getBody().isEmpty()) {
                for (Map<String, Object> emailEntry : response.getBody()) {
                    if (Boolean.TRUE.equals(emailEntry.get("primary"))) {
                        return (String) emailEntry.get("email");
                    }
                }
            }
        }
        return null;

    }
}
