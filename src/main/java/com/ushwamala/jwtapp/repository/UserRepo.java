package com.ushwamala.jwtapp.repository;

import java.util.Optional;

import com.ushwamala.jwtapp.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    public Optional<User> findByEmail(String email);
}
