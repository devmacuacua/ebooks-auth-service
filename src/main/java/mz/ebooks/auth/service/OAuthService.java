package mz.ebooks.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mz.ebooks.auth.dto.AuthResponse;
import mz.ebooks.auth.entity.OAuthAccount;
import mz.ebooks.auth.entity.RefreshToken;
import mz.ebooks.auth.entity.User;
import mz.ebooks.auth.messaging.AuthEventPublisher;
import mz.ebooks.auth.repository.OAuthAccountRepository;
import mz.ebooks.auth.repository.RefreshTokenRepository;
import mz.ebooks.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthService {

    private final OAuthAccountRepository oAuthAccountRepository;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final UserService userService;
    private final AuthEventPublisher eventPublisher;

    @Value("${app.jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    /**
     * Called after a successful OAuth2 login. Resolves or creates the local user,
     * upserts the OAuth account record, generates JWTs, publishes an event and
     * returns a ready-to-use AuthResponse.
     *
     * @param oauthUser      populated OAuth2User from the provider
     * @param registrationId Spring Security registration id (e.g. "google", "facebook")
     * @return AuthResponse containing access/refresh tokens and user details
     */
    @Transactional
    public AuthResponse handleOAuthSuccess(OAuth2User oauthUser, String registrationId) {

        // ── 1. Extract provider-specific attributes ──────────────────────────
        String email = oauthUser.getAttribute("email");
        String name  = oauthUser.getAttribute("name");
        String avatar;
        String providerAccountId;

        if ("google".equalsIgnoreCase(registrationId)) {
            avatar            = oauthUser.getAttribute("picture");
            providerAccountId = oauthUser.getAttribute("sub");
        } else if ("facebook".equalsIgnoreCase(registrationId)) {
            // Facebook returns picture as a nested map: { data: { url: "..." } }
            Object pictureAttr = oauthUser.getAttribute("picture");
            if (pictureAttr instanceof Map<?, ?> pictureMap) {
                Object dataObj = pictureMap.get("data");
                if (dataObj instanceof Map<?, ?> dataMap) {
                    avatar = dataMap.get("url") instanceof String s ? s : null;
                } else {
                    avatar = null;
                }
            } else {
                avatar = pictureAttr instanceof String s ? s : null;
            }
            Object idAttr = oauthUser.getAttribute("id");
            providerAccountId = idAttr != null ? idAttr.toString() : null;
        } else {
            // Generic fallback
            avatar            = oauthUser.getAttribute("picture");
            providerAccountId = oauthUser.getAttribute("sub");
        }

        // ── 2 & 3. Resolve user via existing OAuth account ───────────────────
        OAuthAccount oauthAccount = oAuthAccountRepository
                .findByProviderAndProviderAccountId(registrationId, providerAccountId)
                .orElse(null);

        User user;
        if (oauthAccount != null) {
            user = oauthAccount.getUser();
        } else {
            // ── 4. No linked account — find by email or create a new user ────
            user = userRepository.findByEmail(email).orElseGet(() -> {
                User newUser = User.builder()
                        .email(email)
                        .name(name != null ? name : email)
                        .avatar(avatar)
                        .role("CUSTOMER")
                        .emailVerified(LocalDateTime.now())
                        .passwordHash(null)
                        .isActive(true)
                        .build();
                User saved = userRepository.save(newUser);
                log.info("Created new user [{}] via OAuth2 provider [{}]", saved.getId(), registrationId);
                return saved;
            });

            // Build the OAuthAccount to be upserted below
            oauthAccount = OAuthAccount.builder()
                    .user(user)
                    .provider(registrationId)
                    .providerAccountId(providerAccountId)
                    .build();
        }

        // ── 5. Upsert OAuthAccount with latest provider account id ───────────
        // Provider access/refresh tokens are not exposed via OAuth2User;
        // they remain null or unchanged from a previous upsert.
        oauthAccount.setUser(user);
        oauthAccount.setProvider(registrationId);
        oauthAccount.setProviderAccountId(providerAccountId);
        oAuthAccountRepository.save(oauthAccount);

        // ── 6. Generate our own access + refresh tokens ──────────────────────
        String accessToken = jwtService.generateAccessToken(
                user.getId().toString(),
                user.getEmail(),
                user.getName(),
                user.getRole()
        );
        String rawRefreshToken = jwtService.generateRefreshToken();

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(user)
                .token(rawRefreshToken)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiryMs / 1000))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        // ── 7. Publish event ─────────────────────────────────────────────────
        eventPublisher.publishEvent("user.oauth-login", Map.of(
                "userId", user.getId().toString(),
                "email", user.getEmail(),
                "provider", registrationId
        ));

        log.info("OAuth2 login successful for user [{}] via [{}]", user.getId(), registrationId);

        // ── 8. Return AuthResponse ───────────────────────────────────────────
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .expiresIn(refreshTokenExpiryMs / 1000)
                .user(userService.toDto(user))
                .build();
    }
}
