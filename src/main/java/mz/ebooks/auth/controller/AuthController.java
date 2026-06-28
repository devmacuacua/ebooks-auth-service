package mz.ebooks.auth.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mz.ebooks.auth.dto.*;
import mz.ebooks.auth.service.AuthService;
import mz.ebooks.auth.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    // ─────────────────────────────────────────────────────────────
    // POST /auth/register  →  201 AuthResponse
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ─────────────────────────────────────────────────────────────
    // POST /auth/login  →  200 AuthResponse
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    // ─────────────────────────────────────────────────────────────
    // POST /auth/refresh  →  200 AuthResponse
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.getRefreshToken()));
    }

    // ─────────────────────────────────────────────────────────────
    // POST /auth/logout  →  204 No Content
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
            @RequestHeader("X-User-Id") String userIdHeader) {

        String accessToken = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7);
        }

        UUID userId = UUID.fromString(userIdHeader);
        authService.logout(accessToken, userId);
        return ResponseEntity.noContent().build();
    }

    // ─────────────────────────────────────────────────────────────
    // GET /auth/verify-email?token=  →  redirect to frontend /email-verified
    // ─────────────────────────────────────────────────────────────

    @GetMapping("/verify-email")
    public void verifyEmail(@RequestParam String token,
                            HttpServletResponse response) throws IOException {
        authService.verifyEmail(token);
        response.sendRedirect(frontendUrl + "/email-verified");
    }

    // ─────────────────────────────────────────────────────────────
    // POST /auth/forgot-password  →  200 {message}
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request.getEmail());
        return ResponseEntity.ok(Map.of("message",
                "If that email is registered you will receive a reset link shortly."));
    }

    // ─────────────────────────────────────────────────────────────
    // POST /auth/reset-password  →  200 {message}
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(Map.of("message", "Password has been reset successfully."));
    }

    // ─────────────────────────────────────────────────────────────
    // GET /auth/me  →  200 UserDto  (requires X-User-Id header from gateway)
    // ─────────────────────────────────────────────────────────────

    @GetMapping("/me")
    public ResponseEntity<UserDto> me(@RequestHeader("X-User-Id") String userIdHeader) {
        UUID userId = UUID.fromString(userIdHeader);
        UserDto userDto = userService.toDto(userService.findById(userId));
        return ResponseEntity.ok(userDto);
    }
}
