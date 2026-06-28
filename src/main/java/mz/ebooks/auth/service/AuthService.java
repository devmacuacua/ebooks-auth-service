package mz.ebooks.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mz.ebooks.auth.dto.*;
import mz.ebooks.auth.entity.EmailVerification;
import mz.ebooks.auth.entity.PasswordReset;
import mz.ebooks.auth.entity.RefreshToken;
import mz.ebooks.auth.entity.User;
import mz.ebooks.auth.messaging.AuthEventPublisher;
import mz.ebooks.auth.repository.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final EmailVerificationRepository emailVerificationRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetRepository passwordResetRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserService userService;
    private final AuthEventPublisher eventPublisher;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Value("${app.jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    // ----------------------------------------------------------------
    // Register
    // ----------------------------------------------------------------

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use");
        }

        User user = User.builder()
                .email(request.getEmail())
                .name(request.getName())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role("CUSTOMER")
                .isActive(true)
                .build();
        user = userRepository.save(user);

        // Create email verification token (valid 24h)
        String verificationToken = UUID.randomUUID().toString();
        EmailVerification verification = EmailVerification.builder()
                .user(user)
                .token(verificationToken)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .used(false)
                .build();
        emailVerificationRepository.save(verification);

        // Publish event so notification-service sends the email
        String verificationUrl = frontendUrl + "/verify-email?token=" + verificationToken;
        eventPublisher.publishEvent("user.registered", Map.of(
                "userId", user.getId().toString(),
                "name", user.getName(),
                "email", user.getEmail(),
                "verificationUrl", verificationUrl
        ));

        return buildAuthResponse(user);
    }

    // ----------------------------------------------------------------
    // Login
    // ----------------------------------------------------------------

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is disabled");
        }

        return buildAuthResponse(user);
    }

    // ----------------------------------------------------------------
    // Refresh token
    // ----------------------------------------------------------------

    @Transactional
    public AuthResponse refreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenAndRevokedFalse(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token"));

        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token has expired");
        }

        User user = refreshToken.getUser();

        // Rotate: delete old refresh token and issue new one
        refreshTokenRepository.delete(refreshToken);

        return buildAuthResponse(user);
    }

    // ----------------------------------------------------------------
    // Logout
    // ----------------------------------------------------------------

    @Transactional
    public void logout(String accessToken, UUID userId) {
        long ttlMs = jwtService.getRemainingTtlMs(accessToken);
        if (ttlMs > 0) {
            jwtService.blacklistToken(accessToken, ttlMs);
        }
        refreshTokenRepository.deleteByUserId(userId);
    }

    // ----------------------------------------------------------------
    // Email verification
    // ----------------------------------------------------------------

    @Transactional
    public void verifyEmail(String token) {
        EmailVerification verification = emailVerificationRepository
                .findByTokenAndUsedFalseAndExpiresAtAfter(token, LocalDateTime.now())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired verification token"));

        verification.setUsed(true);
        emailVerificationRepository.save(verification);

        User user = verification.getUser();
        user.setEmailVerified(LocalDateTime.now());
        userRepository.save(user);

        eventPublisher.publishEvent("user.email-verified", Map.of(
                "userId", user.getId().toString(),
                "email", user.getEmail()
        ));

        log.info("Email verified for user {}", user.getEmail());
    }

    // ----------------------------------------------------------------
    // Forgot password
    // ----------------------------------------------------------------

    @Transactional
    public void forgotPassword(String email) {
        // Silently ignore if user not found to avoid user enumeration
        userRepository.findByEmail(email).ifPresent(user -> {
            String resetToken = UUID.randomUUID().toString();
            PasswordReset passwordReset = PasswordReset.builder()
                    .user(user)
                    .token(resetToken)
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .used(false)
                    .build();
            passwordResetRepository.save(passwordReset);

            String resetUrl = frontendUrl + "/reset-password?token=" + resetToken;
            eventPublisher.publishEvent("user.password-reset-requested", Map.of(
                    "email", user.getEmail(),
                    "name", user.getName(),
                    "resetUrl", resetUrl
            ));

            log.info("Password reset requested for user {}", email);
        });
    }

    // ----------------------------------------------------------------
    // Reset password
    // ----------------------------------------------------------------

    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordReset passwordReset = passwordResetRepository
                .findByTokenAndUsedFalseAndExpiresAtAfter(token, LocalDateTime.now())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired reset token"));

        User user = passwordReset.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordReset.setUsed(true);
        passwordResetRepository.save(passwordReset);

        // Revoke all existing refresh tokens for security
        refreshTokenRepository.deleteByUserId(user.getId());

        log.info("Password reset completed for user {}", user.getEmail());
    }

    // ----------------------------------------------------------------
    // Helper: build auth response with new tokens
    // ----------------------------------------------------------------

    private AuthResponse buildAuthResponse(User user) {
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

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .expiresIn(refreshTokenExpiryMs / 1000)
                .user(userService.toDto(user))
                .build();
    }
}
