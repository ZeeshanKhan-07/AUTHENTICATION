package com.auth.authentication.dto;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.auth.authentication.enums.Provider;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {

    private UUID id;

    private String email;

    private String name;

    private String password;

    private String profile_img;

    private boolean enable = true;

    private Instant createdAt = Instant.now();

    private Instant updatedAt = Instant.now();

    private Provider provider = Provider.LOCAL;

    private Set<RoleDTO> roles = new HashSet<>();
}
