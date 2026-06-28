package mz.ebooks.auth.service;

import mz.ebooks.auth.dto.ChangePasswordRequest;
import mz.ebooks.auth.dto.NotificationPrefsDto;
import mz.ebooks.auth.dto.UpdateProfileRequest;
import mz.ebooks.auth.dto.UserDto;
import mz.ebooks.auth.entity.User;
import mz.ebooks.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;

    @InjectMocks UserService userService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("user@test.com")
                .name("Original Name")
                .passwordHash("$2a$10$originalHash")
                .phone("841234567")
                .role("CUSTOMER")
                .isActive(true)
                .notifOrderUpdates(true)
                .notifNewBooks(false)
                .notifSubscriptionAlerts(true)
                .notifPromotions(false)
                .build();
    }

    // ── updateProfile ─────────────────────────────────────────────────────────

    @Test
    void updateProfile_updatesNameAndPhone() {
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setName("New Name");
        req.setPhone("851111222");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDto result = userService.updateProfile(user.getId(), req);

        assertThat(result.getName()).isEqualTo("New Name");
        assertThat(result.getPhone()).isEqualTo("851111222");
    }

    @Test
    void updateProfile_doesNotOverrideName_whenBlank() {
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setName("   ");
        req.setPhone("851111222");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDto result = userService.updateProfile(user.getId(), req);

        assertThat(result.getName()).isEqualTo("Original Name");
    }

    @Test
    void updateProfile_updatesAvatar_whenProvided() {
        UpdateProfileRequest req = new UpdateProfileRequest();
        req.setAvatar("https://cdn.example.com/avatar.jpg");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDto result = userService.updateProfile(user.getId(), req);

        assertThat(result.getAvatar()).isEqualTo("https://cdn.example.com/avatar.jpg");
    }

    @Test
    void updateProfile_throwsNotFound_whenUserDoesNotExist() {
        UUID unknown = UUID.randomUUID();
        when(userRepository.findById(unknown)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.updateProfile(unknown, new UpdateProfileRequest()))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND));
    }

    // ── changePassword ────────────────────────────────────────────────────────

    @Test
    void changePassword_updatesPasswordHash_whenCurrentPasswordCorrect() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("currentPass");
        req.setNewPassword("newPass123");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("currentPass", user.getPasswordHash())).thenReturn(true);
        when(passwordEncoder.encode("newPass123")).thenReturn("$2a$new");
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        userService.changePassword(user.getId(), req);

        assertThat(user.getPasswordHash()).isEqualTo("$2a$new");
        verify(userRepository).save(user);
    }

    @Test
    void changePassword_throwsUnprocessableEntity_whenCurrentPasswordWrong() {
        ChangePasswordRequest req = new ChangePasswordRequest();
        req.setCurrentPassword("wrong");
        req.setNewPassword("newPass123");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", user.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> userService.changePassword(user.getId(), req))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY));

        verify(userRepository, never()).save(any());
    }

    // ── notificationPrefs ─────────────────────────────────────────────────────

    @Test
    void getNotificationPrefs_returnsCurrentPrefsFromUser() {
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        NotificationPrefsDto prefs = userService.getNotificationPrefs(user.getId());

        assertThat(prefs.isOrderUpdates()).isTrue();
        assertThat(prefs.isNewBooks()).isFalse();
        assertThat(prefs.isSubscriptionAlerts()).isTrue();
        assertThat(prefs.isPromotions()).isFalse();
    }

    @Test
    void updateNotificationPrefs_savesNewPrefsAndReturnsDto() {
        NotificationPrefsDto newPrefs = NotificationPrefsDto.builder()
                .orderUpdates(false)
                .newBooks(true)
                .subscriptionAlerts(false)
                .promotions(true)
                .build();

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        NotificationPrefsDto result = userService.updateNotificationPrefs(user.getId(), newPrefs);

        assertThat(user.isNotifOrderUpdates()).isFalse();
        assertThat(user.isNotifNewBooks()).isTrue();
        assertThat(user.isNotifPromotions()).isTrue();
        assertThat(result).isEqualTo(newPrefs);
    }

    // ── toDto ─────────────────────────────────────────────────────────────────

    @Test
    void toDto_mapsAllFields() {
        UserDto dto = userService.toDto(user);

        assertThat(dto.getId()).isEqualTo(user.getId());
        assertThat(dto.getName()).isEqualTo(user.getName());
        assertThat(dto.getEmail()).isEqualTo(user.getEmail());
        assertThat(dto.getPhone()).isEqualTo(user.getPhone());
        assertThat(dto.getRole()).isEqualTo(user.getRole());
    }
}
