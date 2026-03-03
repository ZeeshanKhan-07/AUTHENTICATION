package com.auth.authentication.service;

import com.auth.authentication.dto.UserDTO;

public interface AuthService {
    UserDTO registerUser(UserDTO userDTO);
}
