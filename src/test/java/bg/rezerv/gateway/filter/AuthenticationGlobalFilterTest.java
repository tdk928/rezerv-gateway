package bg.rezerv.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import bg.rezerv.gateway.config.AuthProperties;
import bg.rezerv.gateway.config.HeaderNames;
import bg.rezerv.gateway.config.JwtProperties;
import bg.rezerv.gateway.security.JwtValidator;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import reactor.core.publisher.Mono;

class AuthenticationGlobalFilterTest {

    private static final String SECRET = "dev-secret-change-me-0123456789abcdef0123456789abcdef";

    private AuthenticationGlobalFilter filter;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        var authProperties = new AuthProperties(List.of(
                "/api/auth/register",
                "/api/auth/login",
                "/api/auth/refresh",
                "/api/business/public/**",
                "/api/bookings/public/**"));
        filter = new AuthenticationGlobalFilter(
                new JwtValidator(new JwtProperties(SECRET)),
                authProperties,
                new ObjectMapper());
        chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
    }

    @Test
    void publicPathIsForwardedWithoutToken() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/auth/login").build());

        filter.filter(exchange, chain).block();

        ServerWebExchange forwarded = capturedExchange();
        assertThat(forwarded.getRequest().getHeaders().getFirst(HeaderNames.X_CORRELATION_ID)).isNotBlank();
        assertThat(forwarded.getRequest().getHeaders().getFirst(HeaderNames.X_USER_ID)).isNull();
    }

    @Test
    void protectedPathWithoutTokenReturns401() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/bookings/my").build());

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("\"status\":401").contains("\"code\":\"UNAUTHORIZED\"").contains("correlationId");
    }

    @Test
    void protectedPathWithInvalidTokenReturns401() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/bookings/my")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer garbage")
                        .build());

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void protectedPathWithValidTokenAttachesContextHeaders() throws Exception {
        var token = token(builder -> builder
                .subject("42")
                .claim("roles", List.of("BUSINESS_OWNER", "CLIENT"))
                .claim("companyId", "7")
                .expirationTime(Date.from(Instant.now().plusSeconds(900))));
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/business/salons")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .build());

        filter.filter(exchange, chain).block();

        HttpHeaders headers = capturedExchange().getRequest().getHeaders();
        assertThat(headers.getFirst(HeaderNames.X_USER_ID)).isEqualTo("42");
        assertThat(headers.getFirst(HeaderNames.X_USER_ROLES)).isEqualTo("BUSINESS_OWNER,CLIENT");
        assertThat(headers.getFirst(HeaderNames.X_COMPANY_ID)).isEqualTo("7");
    }

    @Test
    void clientSuppliedContextHeadersAreStripped() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/business/public/salons")
                        .header(HeaderNames.X_USER_ID, "999")
                        .header(HeaderNames.X_USER_ROLES, "PLATFORM_ADMIN")
                        .header(HeaderNames.X_COMPANY_ID, "1")
                        .build());

        filter.filter(exchange, chain).block();

        HttpHeaders headers = capturedExchange().getRequest().getHeaders();
        assertThat(headers.getFirst(HeaderNames.X_USER_ID)).isNull();
        assertThat(headers.getFirst(HeaderNames.X_USER_ROLES)).isNull();
        assertThat(headers.getFirst(HeaderNames.X_COMPANY_ID)).isNull();
    }

    @Test
    void existingCorrelationIdIsPreserved() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/auth/login")
                        .header(HeaderNames.X_CORRELATION_ID, "corr-123")
                        .build());

        filter.filter(exchange, chain).block();

        assertThat(capturedExchange().getRequest().getHeaders().getFirst(HeaderNames.X_CORRELATION_ID))
                .isEqualTo("corr-123");
    }

    private ServerWebExchange capturedExchange() {
        var captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());
        return captor.getValue();
    }

    private static String token(java.util.function.UnaryOperator<JWTClaimsSet.Builder> claims) throws Exception {
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.apply(new JWTClaimsSet.Builder()).build());
        jwt.sign(new MACSigner(SECRET.getBytes()));
        return jwt.serialize();
    }
}
