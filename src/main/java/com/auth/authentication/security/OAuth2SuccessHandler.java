package com.auth.authentication.security;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.auth.authentication.entity.RefreshToken;
import com.auth.authentication.entity.User;
import com.auth.authentication.enums.Provider;
import com.auth.authentication.repository.RefreshTokenRepository;
import com.auth.authentication.repository.UserRepository;
import com.auth.authentication.service.CookieService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        logger.info("Authentication successful");

        OAuth2User oAuthUser = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";

        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("OAuth Provider: {}", registrationId);

        User user = null;

        switch (registrationId) {

            case "google":

                String googleId = oAuthUser.getAttribute("sub");
                String email = oAuthUser.getAttribute("email");
                String name = oAuthUser.getAttribute("name");
                String picture = oAuthUser.getAttribute("picture");

                Optional<User> existingUser = userRepository.findByEmail(email);

                if (existingUser.isPresent()) {

                    user = existingUser.get();
                    logger.info("User already exists: ", user.getEmail());

                } else {

                    user = User.builder()
                            .email(email)
                            .name(name)
                            .profile_img(picture)
                            .enable(true)
                            .provider(Provider.GOOGLE)
                            .providerId(googleId)
                            .build();

                    userRepository.save(user);

                    logger.info("New user saved in database");
                }

                break;

            default:
                logger.error("Unsupported OAuth provider: {}", registrationId);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Unsupported OAuth provider");
                return;
        }

        String jti = UUID.randomUUID().toString();

        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTokenExpiration()))
                .build();

        refreshTokenRepository.save(refreshTokenOb);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        cookieService.attachRefreshCookie(
                response,
                refreshToken,
                (int) jwtService.getRefreshTokenExpiration());

        response.getWriter().write("Login Successful");
    }
}