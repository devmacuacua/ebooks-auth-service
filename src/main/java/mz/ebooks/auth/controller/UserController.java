package mz.ebooks.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import mz.ebooks.auth.dto.ChangePasswordRequest;
import mz.ebooks.auth.dto.NotificationPrefsDto;
import mz.ebooks.auth.dto.UpdateProfileRequest;
import mz.ebooks.auth.dto.UserDto;
import mz.ebooks.auth.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // ── GET /users/me ──────────────────────────────────────────────────────────

    @GetMapping("/me")
    public ResponseEntity<UserDto> getMe(@RequestHeader("X-User-Id") String userId) {
        return ResponseEntity.ok(userService.toDto(userService.findById(UUID.fromString(userId))));
    }

    // ── PUT /users/profile  (frontend alias for PATCH /users/me) ──────────────

    @PutMapping("/profile")
    public ResponseEntity<UserDto> updateProfile(
            @RequestHeader("X-User-Id") String userId,
            @Valid @RequestBody UpdateProfileRequest request) {
        return ResponseEntity.ok(userService.updateProfile(UUID.fromString(userId), request));
    }

    // ── PATCH /users/me  (kept for backwards compat) ──────────────────────────

    @PatchMapping("/me")
    public ResponseEntity<UserDto> updateMe(
            @RequestHeader("X-User-Id") String userId,
            @Valid @RequestBody UpdateProfileRequest request) {
        return ResponseEntity.ok(userService.updateProfile(UUID.fromString(userId), request));
    }

    // ── PUT /users/password ────────────────────────────────────────────────────

    @PutMapping("/password")
    public ResponseEntity<Void> changePassword(
            @RequestHeader("X-User-Id") String userId,
            @Valid @RequestBody ChangePasswordRequest request) {
        userService.changePassword(UUID.fromString(userId), request);
        return ResponseEntity.noContent().build();
    }

    // ── GET /users/notifications ───────────────────────────────────────────────

    @GetMapping("/notifications")
    public ResponseEntity<NotificationPrefsDto> getNotificationPrefs(
            @RequestHeader("X-User-Id") String userId) {
        return ResponseEntity.ok(userService.getNotificationPrefs(UUID.fromString(userId)));
    }

    // ── PUT /users/notifications ───────────────────────────────────────────────

    @PutMapping("/notifications")
    public ResponseEntity<NotificationPrefsDto> updateNotificationPrefs(
            @RequestHeader("X-User-Id") String userId,
            @RequestBody NotificationPrefsDto prefs) {
        return ResponseEntity.ok(userService.updateNotificationPrefs(UUID.fromString(userId), prefs));
    }

    // ── GET /users/{id}  (admin only) ─────────────────────────────────────────

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(
            @PathVariable UUID id,
            @RequestHeader(value = "X-User-Role", required = false) String userRole) {

        if (!"ADMIN".equalsIgnoreCase(userRole)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Admin role required to access this resource");
        }
        return ResponseEntity.ok(userService.toDto(userService.findById(id)));
    }
}
