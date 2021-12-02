package thib.training.SpringSecurityDemo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.security.Principal;
import java.util.Map;
import java.util.Objects;

@RestController
public class LoginController {

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Autowired
    public LoginController(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
    }

    @RequestMapping("/**")
    @RolesAllowed("USER")
    String getUser() {
        return "Hello, user";
    }

    @RequestMapping("/admin")
    @RolesAllowed({"ADMIN", "USER"})
    String getAdmin() {
        return "Hello, admin";
    }

    @RequestMapping("/*")
    String getUserInfo(Principal principal) {
        if (principal instanceof UsernamePasswordAuthenticationToken) {
            return getUserNameAndPAssword((UsernamePasswordAuthenticationToken)principal).toString();
        }
        if (principal instanceof OAuth2AuthenticationToken) {
            return Objects.
                    requireNonNull(getOauth2LoginInfo(principal)).toString();
        }
        return null;
    }


    private StringBuffer getOauth2LoginInfo(Principal oAuth2AuthenticationToken) {
        StringBuffer stringBuffer = new StringBuffer();
        OAuth2AuthorizedClient oAuth2AuthorizedClient = this.oAuth2AuthorizedClientService
                .loadAuthorizedClient(((OAuth2AuthenticationToken)oAuth2AuthenticationToken).getAuthorizedClientRegistrationId(),
                        ((OAuth2AuthenticationToken)oAuth2AuthenticationToken).getName());
        Map<String, Object> userDetails = ((OAuth2AuthenticationToken) oAuth2AuthenticationToken).getPrincipal().getAttributes();
//                String userToken = Objects.requireNonNull(oAuth2AuthorizedClient.getAccessToken().getTokenValue());
        stringBuffer.append("Welcome" + userDetails.get("login") + "<br><br>");
        stringBuffer.append("email" +  userDetails.get("email") + "<br><br>");
//            stringBuffer.append("Access Token " + userToken+ "<br><br>"); never show this

        OidcIdToken idToken = getIdToken(((OAuth2AuthenticationToken) oAuth2AuthenticationToken).getPrincipal());

        if (idToken != null) {
            stringBuffer.append("Id token : " + idToken.getTokenValue());

            Map<String, Object> claims = idToken.getClaims();

            for (String key : claims.keySet()) {
                stringBuffer.append("        " + key + ": " + claims.get(key) + "<br><br>");
            }
        }

        return stringBuffer;
    }

    private StringBuffer getUserNameAndPAssword(UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) {
        StringBuffer stringBuffer = new StringBuffer();

        if (usernamePasswordAuthenticationToken.isAuthenticated()) {
            User u = (User) usernamePasswordAuthenticationToken.getPrincipal();
            stringBuffer.append("Welcome, " + u.getUsername());
        }
        else {
            stringBuffer.append("NA");
        }
        return stringBuffer;
    }

    OidcIdToken getIdToken(OAuth2User principal) {
        if (principal instanceof DefaultOidcUser) {
            return ((DefaultOidcUser) principal).getIdToken();
        }
        return null;
    }

}
