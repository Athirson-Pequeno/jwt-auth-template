package org.tizo.estudo_autenticacao.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.tizo.estudo_autenticacao.auth.dto.AuthResponse;
import org.tizo.estudo_autenticacao.auth.dto.LoginRequest;
import org.tizo.estudo_autenticacao.auth.dto.RefreshRequest;
import org.tizo.estudo_autenticacao.auth.dto.RegisterRequest;
import org.tizo.estudo_autenticacao.model.*;
import org.tizo.estudo_autenticacao.repository.TokenRepository;
import org.tizo.estudo_autenticacao.repository.UserRepository;

import java.util.List;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private JwtService jwtService;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;

    public AuthService(
            UserRepository userRepository,
            TokenRepository tokenRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public AuthResponse register(RegisterRequest registerRequest) {
        User user = User.builder()
                .username(registerRequest.username())
                .password(passwordEncoder.encode(registerRequest.password()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        String accessToken = jwtService.generateAccessToken(new UserDetailsImpl(user));
        String refreshToken = jwtService.generateRefreshToken(new UserDetailsImpl(user));
        saveToken(user, refreshToken);
        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse authenticate(LoginRequest loginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password())
        );

        User user = userRepository.findByUsername(loginRequest.username()).orElseThrow();

        revokeAllUserTokens(user);

        String accessToken = jwtService.generateAccessToken(new UserDetailsImpl(user));
        String refreshToken = jwtService.generateRefreshToken(new UserDetailsImpl(user));

        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse refreshToken(RefreshRequest refreshRequest) {
        String refreshToken = refreshRequest.refreshToken();
        String username = jwtService.extractUsername(refreshToken);

        User user = userRepository.findByUsername(username).orElseThrow();

        if(!jwtService.isTokenValid(refreshToken, new UserDetailsImpl(user))) throw new RuntimeException("Token invalido ou expirado");

        String accessToken = jwtService.generateAccessToken(new UserDetailsImpl(user));
        revokeAllUserTokens(user);
        saveToken(user, accessToken);

        return new AuthResponse(accessToken, refreshToken);
    }

    private void revokeAllUserTokens(User user) {
        List<Token> validTokens = tokenRepository.findAllByUserAndExpiredFalseAndRevokedFalse(user);

        for(Token token : validTokens) {
            token.setRevoked(true);
            token.setExpired(true);
        }

        tokenRepository.saveAll(validTokens);
    }

    private void saveToken(User user, String accessToken) {
        Token token = Token.builder()
                .user(user)
                .token(accessToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
    }
}
