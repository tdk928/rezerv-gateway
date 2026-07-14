package bg.rezerv.gateway.web;

import java.time.Instant;

/** Единен формат на грешките за всички REZERV сервизи (REZERV.md §2.6). */
public record ErrorResponse(int status, String code, String message, String correlationId, Instant timestamp) {

    public static ErrorResponse unauthorized(String message, String correlationId) {
        return new ErrorResponse(401, "UNAUTHORIZED", message, correlationId, Instant.now());
    }
}
