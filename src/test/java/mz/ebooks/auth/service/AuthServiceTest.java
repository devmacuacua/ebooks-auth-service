package mz.ebooks.auth.service;

import mz.ebooks.auth.dto.AuthResponse;
import mz.ebooks.auth.dto.RegisterRequest;
import mz.ebooks.auth.dto.LoginRequest;
import mz.ebooks.auth.dto.UserDto;
import mz.ebooks.auth.entity.EmailVerification;
import mz.ebooks.auth.entity.PasswordReset;
import mz.ebooks.auth.entity.RefreshToken;
import mz.ebooks.auth.entity.User;
import mz.ebooks.auth.messaging.AuthEventPublisher;
import mz.ebooks.auth.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock UserRepository userRepository;
    @Mock EmailVerificationRepository emailVerificationRepository;
    @Mock RefreshTokenRepository refreshTokenRepository;
    @Mock PasswordResetRepository passwordResetRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock JwtService jwtService;
    @Mock UserService userService;
    @Mock AuthEventPublisher eventPublisher;

    @InjectMocks AuthService authService;

    private User activeUser;
    private UserDto userDto;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "frontendUrl", "http://localhost:3000");
        ReflectionTestUtils.setField(authService, "refreshTokenExpiryMs", 604_800_000L);

        activeUser = User.builder()
                .id(UUID.randomUUID())
                .email("user@test.com")
                .name("Test User")
                .passwordHash("$2a$10$hashed")
                .role("CUSTOMER")
                .isActive(true)
                .build();

        userDto = UserDto.builder()
                .id(activeUser.getId())
                .name(activeUser.getName())
                .email(activeUser.getEmail())
                .role(activeUser.getRole())
                .build();
    }

    // ── register ──────────────────────────────────────────────────────────────

    @Test
    void register_createsUserAndReturnsTokens() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("new@test.com");
        req.setName("New User");
        req.setPassword("Secret1234");

        when(userRepository.existsByEmail("new@test.com")).thenReturn(false);
        when(passwordEncoder.encode("Secret1234")).thenReturn("$2a$10$encoded");
        User savedUser = User.builder().id(UUID.randomUUID()).email("new@test.com").name("New User")
                .passwordHash("$2a$10$encoded").role("CUSTOMER").isActive(true).build();
        when(userRepository.save(any())).thenReturn(savedUser);
        when(emailVerificationRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(jwtService.generateAccessToken(any(), any(), any(), any())).thenReturn("access-token");
        when(jwtService.generateRefreshToken()).thenReturn("refresh-token");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.toDto(savedUser)).thenReturn(userDto);

        AuthResponse response = authService.register(req);

        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        verify(emailVerificationRepository).save(any(EmailVerification.class));
        verify(eventPublisher).publishEvent(eq("user.registered"), any());
    }

    @Test
    void register_throwsConflict_whenEmailAlreadyUsed() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("user@test.com");
        req.setName("Any");
        req.setPassword("Secret1234");
        when(userRepository.existsByEmail("user@test.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.CONFLICT));

        verify(userRepository, never()).save(any());
    }

    @Test
    void register_publishesVerificationUrl_withFrontendUrl() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("new2@test.com");
        req.setName("New2");
        req.setPassword("Secret1234");

        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hash");
        User saved = User.builder().id(UUID.randomUUID()).email("new2@test.com").name("New2")
                .role("CUSTOMER").isActive(true).build();
        when(userRepository.save(any())).thenReturn(saved);
        when(emailVerificationRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(jwtService.generateAccessToken(any(), any(), any(), any())).thenReturn("tok");
        when(jwtService.generateRefreshToken()).thenReturn("ref");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.toDto(any())).thenReturn(userDto);

        authService.register(req);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<java.util.Map<String, Object>> captor = ArgumentCaptor.forClass(java.util.Map.class);
        verify(eventPublisher).publishEvent(eq("user.registered"), captor.capture());
        assertThat(captor.getValue().get("verificationUrl").toString())
                .startsWith("http://localhost:3000/verify-email?token=");
    }

    // ── login ─────────────────────────────────────────────────────────────────

    @Test
    void login_returnsTokens_whenCredentialsValid() {
        LoginRequest req = new LoginRequest();
        req.setEmail("user@test.com");
        req.setPassword("correct-pass");

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("correct-pass", activeUser.getPasswordHash())).thenReturn(true);
        when(jwtService.generateAccessToken(any(), any(), any(), any())).thenReturn("access-token");
        when(jwtService.generateRefreshToken()).thenReturn("refresh-token");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(userService.toDto(activeUser)).thenReturn(userDto);

        AuthResponse response = authService.login(req);

        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getUser().getEmail()).isEqualTo("user@test.com");
    }

    @Test
    void login_throwsUnauthorized_whenUserNotFound() {
        LoginRequest req = new LoginRequest();
        req.setEmail("unknown@test.com");
        req.setPassword("pass");
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    void login_throwsUnauthorized_whenPasswordWrong() {
        LoginRequest req = new LoginRequest();
        req.setEmail("user@test.com");
        req.setPassword("wrong");
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches("wrong", activeUser.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    void login_throwsForbidden_whenUserDisabled() {
        activeUser.setActive(false);
        LoginRequest req = new LoginRequest();
        req.setEmail("user@test.com");
        req.setPassword("correct");
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches(any(), any())).thenReturn(true);

        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN));
    }

    // ── verifyEmail ───────────────────────────────────────────────────────────

    @Test
    void verifyEmail_marksTokenUsedAndSetsEmailVerified() {
        EmailVerification verification = EmailVerification.builder()
                .user(activeUser)
                .token("valid-token")
                .expiresAt(LocalDateTime.now().plusHours(1))
                .used(false)
                .build();

        when(emailVerificationRepository.findByTokenAndUsedFalseAndExpiresAtAfter(
                eq("valid-token"), any())).thenReturn(Optional.of(verification));
        when(emailVerificationRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.verifyEmail("valid-token");

        assertThat(verification.isUsed()).isTrue();
        assertThat(activeUser.getEmailVerified()).isNotNull();
        verify(eventPublisher).publishEvent(eq("user.email-verified"), any());
    }

    @Test
    void verifyEmail_throwsBadRequest_whenTokenInvalid() {
        when(emailVerificationRepository.findByTokenAndUsedFalseAndExpiresAtAfter(
                anyString(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyEmail("bad-token"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));
    }

    // ── forgotPassword ────────────────────────────────────────────────────────

    @Test
    void forgotPassword_savesResetTokenAndPublishesEvent_whenUserExists() {
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(activeUser));
        when(passwordResetRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.forgotPassword("user@test.com");

        verify(passwordResetRepository).save(any(PasswordReset.class));
        verify(eventPublisher).publishEvent(eq("user.password-reset-requested"), any());
    }

    @Test
    void forgotPassword_doesNothing_whenUserNotFound() {
        when(userRepository.findByEmail("unknown@test.com")).thenReturn(Optional.empty());

        authService.forgotPassword("unknown@test.com");

        verify(passwordResetRepository, never()).save(any());
        verify(eventPublisher, never()).publishEvent(any(), any());
    }

    // ── resetPassword ─────────────────────────────────────────────────────────

    @Test
    void resetPassword_updatesPasswordAndRevokesRefreshTokens() {
        PasswordReset reset = PasswordReset.builder()
                .user(activeUser)
                .token("valid-reset")
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .used(false)
                .build();

        when(passwordResetRepository.findByTokenAndUsedFalseAndExpiresAtAfter(
                eq("valid-reset"), any())).thenReturn(Optional.of(reset));
        when(passwordEncoder.encode("NewPass123")).thenReturn("$2a$new");
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(passwordResetRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        authService.resetPassword("valid-reset", "NewPass123");

        assertThat(activeUser.getPasswordHash()).isEqualTo("$2a$new");
        assertThat(reset.isUsed()).isTrue();
        verify(refreshTokenRepository).deleteByUserId(activeUser.getId());
    }

    @Test
    void resetPassword_throwsBadRequest_whenTokenExpiredOrUsed() {
        when(passwordResetRepository.findByTokenAndUsedFalseAndExpiresAtAfter(
                anyString(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resetPassword("stale-token", "NewPass123"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));
    }

    // ── logout ────────────────────────────────────────────────────────────────

    @Test
    void logout_blacklistsAccessTokenAndDeletesRefreshTokens() {
        String token = "valid.access.token";
        UUID userId = activeUser.getId();
        when(jwtService.getRemainingTtlMs(token)).thenReturn(60_000L);

        authService.logout(token, userId);

        verify(jwtService).blacklistToken(token, 60_000L);
        verify(refreshTokenRepository).deleteByUserId(userId);
    }

    @Test
    void logout_doesNotBlacklist_whenTokenAlreadyExpired() {
        String token = "expired.token";
        UUID userId = activeUser.getId();
        when(jwtService.getRemainingTtlMs(token)).thenReturn(0L);

        authService.logout(token, userId);

        verify(jwtService, never()).blacklistToken(any(), anyLong());
        verify(refreshTokenRepository).deleteByUserId(userId);
    }
}
