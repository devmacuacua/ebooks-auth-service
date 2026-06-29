package mz.ebooks.auth.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class UserDto {

    private UUID id;
    private String name;
    private String email;
    private String phone;
    private String avatar;
    private String role;
    private LocalDateTime emailVerified;
    private boolean active;
}
