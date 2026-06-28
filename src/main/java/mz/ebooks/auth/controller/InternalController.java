package mz.ebooks.auth.controller;

import lombok.RequiredArgsConstructor;
import mz.ebooks.auth.dto.UserDto;
import mz.ebooks.auth.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Service-to-service endpoints — never routed through the API gateway.
 * Only reachable inside the Docker/K8s network.
 */
@RestController
@RequestMapping("/auth/internal")
@RequiredArgsConstructor
public class InternalController {

    private final UserService userService;

    @GetMapping("/users/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.toDto(userService.findById(id)));
    }
}
