package com.auth.authentication.dto;

public record LoginRequest (
    String email,
    String password
) {
    
}
