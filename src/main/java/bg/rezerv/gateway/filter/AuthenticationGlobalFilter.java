package bg.rezerv.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;

import tools.jackson.databind.ObjectMapper;

import bg.rezerv.gateway.config.AuthProperties;
import bg.rezerv.gateway.config.HeaderNames;
import bg.rezerv.gateway.security.InvalidTokenException;
import bg.rezerv.gateway.security.JwtClaims;
import bg.rezerv.gateway.security.JwtValidator;
import bg.rezerv.gateway.web.ErrorResponse;
import reactor.core.publisher.Mono;

/**
 * Централният филтър на gateway (REZERV.md §4 GATEWAY flow):
 * 1. Осигурява X-Correlation-Id (генерира, ако липсва).
 * 2. Маха client-supplied context headers (никой отвън не може да се представи за user).
 * 3. Публичен path → forward директно; иначе валидира JWT → 401 тук или закача X-* headers.
 */
@Component
public class AuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationGlobalFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtValidator jwtValidator;
    private final AuthProperties authProperties;
    private final ObjectMapper objectMapper;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public AuthenticationGlobalFilter(JwtValidator jwtValidator,
                                      AuthProperties authProperties,
                                      ObjectMapper objectMapper) {
        this.jwtValidator = jwtValidator;
        this.authProperties = authProperties;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String correlationId = resolveCorrelationId(request);
        String path = request.getPath().value();

        ServerHttpRequest.Builder mutated = request.mutate()
                .headers(headers -> {
                    headers.remove(HeaderNames.X_USER_ID);
                    headers.remove(HeaderNames.X_USER_ROLES);
                    headers.remove(HeaderNames.X_COMPANY_ID);
                    headers.set(HeaderNames.X_CORRELATION_ID, correlationId);
                });

        if (isPublicPath(path)) {
            return chain.filter(exchange.mutate().request(mutated.build()).build());
        }

        String token = extractBearerToken(request.getHeaders());
        if (token == null) {
            return unauthorized(exchange, "Missing Authorization header", correlationId);
        }

        JwtClaims claims;
        try {
            claims = jwtValidator.validate(token);
        } catch (InvalidTokenException e) {
            log.debug("Rejected token for path {} [{}]: {}", path, correlationId, e.getMessage());
            return unauthorized(exchange, "Invalid or expired token", correlationId);
        }

        mutated.headers(headers -> {
            headers.set(HeaderNames.X_USER_ID, claims.userId());
            headers.set(HeaderNames.X_USER_ROLES, claims.rolesAsHeader());
            if (claims.companyId() != null) {
                headers.set(HeaderNames.X_COMPANY_ID, claims.companyId());
            }
        });

        return chain.filter(exchange.mutate().request(mutated.build()).build());
    }

    private boolean isPublicPath(String path) {
        return authProperties.publicPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private String resolveCorrelationId(ServerHttpRequest request) {
        String incoming = request.getHeaders().getFirst(HeaderNames.X_CORRELATION_ID);
        return (incoming == null || incoming.isBlank()) ? UUID.randomUUID().toString() : incoming;
    }

    private String extractBearerToken(HttpHeaders headers) {
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = authorization.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message, String correlationId) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(HeaderNames.X_CORRELATION_ID, correlationId);

        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(ErrorResponse.unauthorized(message, correlationId));
        } catch (Exception e) {
            body = "{\"status\":401,\"code\":\"UNAUTHORIZED\"}".getBytes(StandardCharsets.UTF_8);
        }
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
