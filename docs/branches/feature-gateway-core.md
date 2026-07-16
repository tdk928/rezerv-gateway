# feature/gateway-core

## Цел

Първоначална имплементация на rezerv-gateway според REZERV.md: единствена публична входна
точка с routing, JWT валидация, context headers и rate limit.

## Направено

- **Maven проект**: Spring Boot 4.1.0, Spring Cloud 2025.1.2 (Gateway 5.x, WebFlux), Java 21,
  nimbus-jose-jwt за JWT, Redis reactive за rate limit, actuator (`health`, `info`, `gateway`).
- **Routing** (`application.yml`, новия namespace `spring.cloud.gateway.server.webflux.*`):
  - `/api/auth/**` → http://localhost:8081 (rezerv-cas)
  - `/api/business/**` → http://localhost:8082 (rezerv-business)
  - `/api/bookings/**` → http://localhost:8083 (rezerv-booking)
  - `StripPrefix=1` глобално (маха `/api`); URI-тата са override-ваеми през env (`CAS_URI` и т.н.).
- **JWT валидация** (`JwtValidator`): HS256 със shared secret (`JWT_SECRET`, dev default от
  REZERV.md §2.2); проверява подпис, expiry, задължителен `sub`; чете `email`, `roles`, `companyId`.
  `companyId` се coerce-ва към string (CAS го издава като string; числови claims от стари
  token-и също минават — иначе Nimbus `getStringClaim` → 401).
- **`AuthenticationGlobalFilter`** (order -100):
  1. осигурява `X-Correlation-Id` (генерира UUID, ако липсва);
  2. маха client-supplied `X-User-Id`/`X-User-Roles`/`X-Company-Id` (anti-spoofing);
  3. публичните paths (`/api/auth/register|login|refresh`, `/api/business/public/**`,
     `/api/bookings/public/**` — конфигурируеми в `rezerv.auth.public-paths`) минават без token;
  4. останалите: валиден Bearer token → закача `X-User-Id`, `X-User-Roles`, `X-Company-Id`;
     невалиден/липсващ → **401 от gateway** с единния error формат (§2.6).
- **Rate limit**: Redis `RequestRateLimiter` per client IP (`ipKeyResolver`), 20 req/s,
  burst 40 (env: `RATE_LIMIT_REPLENISH`/`RATE_LIMIT_BURST`); Redis на localhost:6380 (rezerv-infra).
- **Записи (records)**: `JwtProperties`, `AuthProperties`, `JwtClaims`, `ErrorResponse`.
  Константи за headers в `HeaderNames`.

## Решения

- Jackson 3 (`tools.jackson.*`) — Boot 4.x вече не ползва `com.fasterxml.jackson.databind`.
- Property namespace-ът на Gateway 5 е `spring.cloud.gateway.server.webflux.*` (старият не bind-ва).
- `/internal/**` не се route-ва изобщо — няма route за него, gateway връща 404.

## Как се тества

- `mvn test` — 13 unit теста (`JwtValidatorTest`, `AuthenticationGlobalFilterTest`): валиден/изтекъл/
  подправен/малформиран token, липсващ `sub`, публични paths, 401 формат, strip на spoofed headers,
  запазване на подаден correlation id.
- Ръчно: `docker compose up -d` в rezerv-infra → `mvn spring-boot:run` → Postman колекцията
  (`postman/`). Проверено: 401 без token (единен формат), 401 с невалиден token, forward с валиден
  token, `X-RateLimit-*` headers присъстват.
