package ru.petproject.ecommerce.user_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.expiration}")
    private int jwtExpirationInMs;

    // Генерация безопасного ключа для HS512
    private final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId())) // Устанавливаем subject (ID пользователя)
                .setIssuedAt(now) // Время создания токена
                .setExpiration(expiryDate) // Время истечения токена
                .signWith(secretKey, SignatureAlgorithm.HS512) // Подписываем токен с использованием безопасного ключа
                .compact();
    }

    public Long getUserIdFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey) // Указываем ключ для проверки подписи
                .build()
                .parseClaimsJws(token) // Парсим токен и проверяем подпись
                .getBody(); // Получаем тело токена (claims)

        return Long.parseLong(claims.getSubject()); // Возвращаем ID пользователя из subject
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey) // Указываем ключ для проверки подписи
                    .build()
                    .parseClaimsJws(authToken); // Парсим токен и проверяем подпись
            return true; // Токен валиден
        } catch (Exception ex) {
            // Логирование ошибки
            System.err.println("Ошибка при валидации токена: " + ex.getMessage());
            return false; // Токен невалиден
        }
    }
}