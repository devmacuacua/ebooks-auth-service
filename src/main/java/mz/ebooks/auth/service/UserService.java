package mz.ebooks.auth.service;

import lombok.RequiredArgsConstructor;
import mz.ebooks.auth.dto.ChangePasswordRequest;
import mz.ebooks.auth.dto.NotificationPrefsDto;
import mz.ebooks.auth.dto.UpdateProfileRequest;
import mz.ebooks.auth.dto.UserDto;
import mz.ebooks.auth.entity.User;
import mz.ebooks.auth.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    @Transactional(readOnly = true)
    public Page<UserDto> listUsers(String search, Pageable pageable) {
        return userRepository.searchUsers(search, pageable).map(this::toDto);
    }

    @Transactional
    public UserDto setActive(UUID userId, boolean active) {
        User user = findById(userId);
        user.setActive(active);
        return toDto(userRepository.save(user));
    }

    @Transactional
    public UserDto updateRole(UUID userId, String role) {
        User user = findById(userId);
        user.setRole(role);
        return toDto(userRepository.save(user));
    }

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    @Transactional
    public UserDto updateProfile(UUID userId, UpdateProfileRequest request) {
        User user = findById(userId);

        if (request.getName() != null && !request.getName().isBlank()) {
            user.setName(request.getName());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        if (request.getAvatar() != null) {
            user.setAvatar(request.getAvatar());
        }

        User saved = userRepository.save(user);
        return toDto(saved);
    }

    @Transactional
    public void changePassword(UUID userId, ChangePasswordRequest req) {
        User user = findById(userId);

        if (user.getPasswordHash() == null ||
                !passwordEncoder.matches(req.getCurrentPassword(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Current password is incorrect");
        }

        user.setPasswordHash(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public NotificationPrefsDto getNotificationPrefs(UUID userId) {
        User user = findById(userId);
        return NotificationPrefsDto.builder()
                .orderUpdates(user.isNotifOrderUpdates())
                .newBooks(user.isNotifNewBooks())
                .subscriptionAlerts(user.isNotifSubscriptionAlerts())
                .promotions(user.isNotifPromotions())
                .build();
    }

    @Transactional
    public NotificationPrefsDto updateNotificationPrefs(UUID userId, NotificationPrefsDto prefs) {
        User user = findById(userId);
        user.setNotifOrderUpdates(prefs.isOrderUpdates());
        user.setNotifNewBooks(prefs.isNewBooks());
        user.setNotifSubscriptionAlerts(prefs.isSubscriptionAlerts());
        user.setNotifPromotions(prefs.isPromotions());
        userRepository.save(user);
        return prefs;
    }

    public UserDto toDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .phone(user.getPhone())
                .avatar(user.getAvatar())
                .role(user.getRole())
                .emailVerified(user.getEmailVerified())
                .active(user.isActive())
                .build();
    }
}
