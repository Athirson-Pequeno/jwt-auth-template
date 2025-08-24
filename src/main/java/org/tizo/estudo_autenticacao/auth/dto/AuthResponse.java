package org.tizo.estudo_autenticacao.auth.dto;

public record AuthResponse(String accessToken, String refreshToken) {
}
