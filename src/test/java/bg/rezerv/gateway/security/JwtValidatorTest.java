package bg.rezerv.gateway.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import bg.rezerv.gateway.config.JwtProperties;

class JwtValidatorTest {

    private static final String SECRET = "dev-secret-change-me-0123456789abcdef0123456789abcdef";
    private static final String OTHER_SECRET = "another-secret-x-0123456789abcdef0123456789abcdefff";

    private final JwtValidator validator = new JwtValidator(new JwtProperties(SECRET));

    @Test
    void validTokenReturnsAllClaims() throws Exception {
        var token = signedToken(SECRET, builder -> builder
                .subject("42")
                .claim("email", "ivan@rezerv.bg")
                .claim("roles", List.of("BUSINESS_OWNER", "CLIENT"))
                .claim("companyId", "7")
                .expirationTime(Date.from(Instant.now().plusSeconds(900))));

        JwtClaims claims = validator.validate(token);

        assertThat(claims.userId()).isEqualTo("42");
        assertThat(claims.email()).isEqualTo("ivan@rezerv.bg");
        assertThat(claims.roles()).containsExactly("BUSINESS_OWNER", "CLIENT");
        assertThat(claims.companyId()).isEqualTo("7");
        assertThat(claims.rolesAsHeader()).isEqualTo("BUSINESS_OWNER,CLIENT");
    }

    @Test
    void missingRolesAndCompanyIdAreTolerated() throws Exception {
        var token = signedToken(SECRET, builder -> builder
                .subject("42")
                .expirationTime(Date.from(Instant.now().plusSeconds(900))));

        JwtClaims claims = validator.validate(token);

        assertThat(claims.roles()).isEmpty();
        assertThat(claims.companyId()).isNull();
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        var token = signedToken(SECRET, builder -> builder
                .subject("42")
                .expirationTime(Date.from(Instant.now().minusSeconds(60))));

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void tokenWithoutExpirationIsRejected() throws Exception {
        var token = signedToken(SECRET, builder -> builder.subject("42"));

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void tokenSignedWithDifferentSecretIsRejected() throws Exception {
        var token = signedToken(OTHER_SECRET, builder -> builder
                .subject("42")
                .expirationTime(Date.from(Instant.now().plusSeconds(900))));

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void tokenWithoutSubjectIsRejected() throws Exception {
        var token = signedToken(SECRET, builder -> builder
                .expirationTime(Date.from(Instant.now().plusSeconds(900))));

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void malformedTokenIsRejected() {
        assertThatThrownBy(() -> validator.validate("not-a-jwt"))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Malformed");
    }

    private static String signedToken(String secret, java.util.function.UnaryOperator<JWTClaimsSet.Builder> claims)
            throws Exception {
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.apply(new JWTClaimsSet.Builder()).build());
        jwt.sign(new MACSigner(secret.getBytes()));
        return jwt.serialize();
    }
}
