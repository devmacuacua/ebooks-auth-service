package mz.ebooks.auth.dto;

import lombok.Data;

@Data
public class UpdateProfileRequest {

    private String name;
    private String phone;
    private String avatar;
}
