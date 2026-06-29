package mz.ebooks.auth.controller;

import lombok.RequiredArgsConstructor;
import mz.ebooks.auth.dto.UserDto;
import mz.ebooks.auth.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<Page<UserDto>> listUsers(
            @RequestHeader(value = "X-User-Role", defaultValue = "") String role,
            @RequestParam(required = false) String search,
            @PageableDefault(size = 20) Pageable pageable) {
        if (!"ADMIN".equals(role)) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(userService.listUsers(search, pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUser(
            @RequestHeader(value = "X-User-Role", defaultValue = "") String role,
            @PathVariable UUID id) {
        if (!"ADMIN".equals(role)) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(userService.toDto(userService.findById(id)));
    }

    @PatchMapping("/{id}/role")
    public ResponseEntity<UserDto> updateRole(
            @RequestHeader(value = "X-User-Role", defaultValue = "") String role,
            @PathVariable UUID id,
            @RequestParam String newRole) {
        if (!"ADMIN".equals(role)) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(userService.updateRole(id, newRole));
    }

    @PatchMapping("/{id}/active")
    public ResponseEntity<UserDto> setActive(
            @RequestHeader(value = "X-User-Role", defaultValue = "") String role,
            @PathVariable UUID id,
            @RequestParam boolean active) {
        if (!"ADMIN".equals(role)) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        return ResponseEntity.ok(userService.setActive(id, active));
    }
}
