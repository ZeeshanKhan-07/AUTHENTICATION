package com.auth.authentication.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.authentication.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID>{
    
}
