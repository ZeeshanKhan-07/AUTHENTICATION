package com.auth.authentication.dto;

public record TokenResponse (
    String accessToken,
    String refreshToken,
    long expiresIn,
    String tokenType,
    UserDTO user
) {
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, UserDTO user) {
        return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", user);
    }
}
