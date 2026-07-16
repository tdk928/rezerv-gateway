package bg.rezerv.gateway.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Path patterns, които gateway forward-ва без JWT (REZERV.md §2.1). */
@ConfigurationProperties("rezerv.auth")
public record AuthProperties(List<String> publicPaths) {
}
