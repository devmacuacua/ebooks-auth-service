package mz.ebooks.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ForgotPasswordRequest {

    @Email(message = "Valid email is required")
    @NotBlank(message = "Email is required")
    private String email;
}
