package bg.rezerv.gateway.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

import bg.rezerv.gateway.config.JwtProperties;

/** Валидира HS256 access tokens, издадени от rezerv-cas (REZERV.md §2.2). */
@Component
public class JwtValidator {

    private final byte[] secret;

    public JwtValidator(JwtProperties properties) {
        this.secret = properties.secret().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * @throws InvalidTokenException при невалиден подпис, изтекъл token или липсващи claims
     */
    public JwtClaims validate(String token) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (Exception e) {
            throw new InvalidTokenException("Malformed token", e);
        }

        if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new InvalidTokenException("Unsupported algorithm: " + jwt.getHeader().getAlgorithm());
        }

        try {
            if (!jwt.verify(new MACVerifier(secret))) {
                throw new InvalidTokenException("Invalid signature");
            }

            var claims = jwt.getJWTClaimsSet();

            Date expiration = claims.getExpirationTime();
            if (expiration == null || expiration.toInstant().isBefore(Instant.now())) {
                throw new InvalidTokenException("Token expired");
            }

            String userId = claims.getSubject();
            if (userId == null || userId.isBlank()) {
                throw new InvalidTokenException("Missing sub claim");
            }

            List<String> roles = claims.getStringListClaim("roles");
            return new JwtClaims(
                    userId,
                    claims.getStringClaim("email"),
                    roles == null ? List.of() : roles,
                    readCompanyId(claims));
        } catch (InvalidTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidTokenException("Token validation failed", e);
        }
    }

    /**
     * CAS трябва да издава companyId като string; стари/грешни token-и може да имат число —
     * Nimbus getStringClaim хвърля за Integer/Long и gateway връщаше 401.
     */
    private static String readCompanyId(com.nimbusds.jwt.JWTClaimsSet claims) {
        Object value = claims.getClaim("companyId");
        return value == null ? null : String.valueOf(value);
    }
}
