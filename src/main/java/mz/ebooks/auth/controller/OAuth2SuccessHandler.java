package mz.ebooks.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mz.ebooks.auth.dto.AuthResponse;
import mz.ebooks.auth.service.OAuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Called by Spring Security after a successful OAuth2 login.
 * Delegates to OAuthService to resolve/create the user, then redirects
 * the browser to the frontend callback URL with the issued tokens.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final OAuthService oAuthService;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = oauthToken.getPrincipal();
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();

        AuthResponse authResponse = oAuthService.handleOAuthSuccess(oauthUser, registrationId);

        String redirectUrl = frontendUrl + "/auth/oauth-callback"
                + "?token=" + URLEncoder.encode(authResponse.getAccessToken(), StandardCharsets.UTF_8)
                + "&refreshToken=" + URLEncoder.encode(authResponse.getRefreshToken(), StandardCharsets.UTF_8);

        log.debug("OAuth2 success — redirecting to frontend callback for user [{}]",
                authResponse.getUser().getId());

        response.sendRedirect(redirectUrl);
    }
}
