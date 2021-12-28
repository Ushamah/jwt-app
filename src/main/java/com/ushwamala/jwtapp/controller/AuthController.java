package com.ushwamala.jwtapp.controller;

import java.util.Collections;
import java.util.Map;

import com.ushwamala.jwtapp.entity.User;
import com.ushwamala.jwtapp.model.UserLoginCredentials;
import com.ushwamala.jwtapp.repository.UserRepo;
import com.ushwamala.jwtapp.security.JWTUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepo userRepo;
    private final JWTUtil jwtUtil;
    private final AuthenticationManager authManager;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepo userRepo, JWTUtil jwtUtil,
            AuthenticationManager authManager,
            PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
        this.authManager = authManager;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public Map<String, Object> registerHandler(@RequestBody User user) {
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        user = userRepo.save(user);
        String token = jwtUtil.generateToken(user.getEmail());

        return Collections.singletonMap("jwt-token", token);
    }

    @PostMapping("/login")
    public Map<String, Object> loginHandler(@RequestBody UserLoginCredentials userLoginCredentials) {
        try {
            final String email = userLoginCredentials.getEmail();
            UsernamePasswordAuthenticationToken authInputToken =
                    new UsernamePasswordAuthenticationToken(email, userLoginCredentials.getPassword());

            authManager.authenticate(authInputToken);

            String token = jwtUtil.generateToken(email);
            return Collections.singletonMap("jwt-token", token);
        }
        catch (AuthenticationException e) {
            throw new RuntimeException("Invalid Login Credentials");
        }
    }
}
