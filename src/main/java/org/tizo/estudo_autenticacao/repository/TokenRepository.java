package org.tizo.estudo_autenticacao.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.tizo.estudo_autenticacao.model.Token;
import org.tizo.estudo_autenticacao.model.User;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    List<Token> findAllByUserAndExpiredFalseAndRevokedFalse(User user);

    Optional<Token> findByToken(String token);
}
