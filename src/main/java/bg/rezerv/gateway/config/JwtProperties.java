package bg.rezerv.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Shared secret за HS256 JWT валидация — същият като в rezerv-cas (env JWT_SECRET). */
@ConfigurationProperties("rezerv.jwt")
public record JwtProperties(String secret) {
}
