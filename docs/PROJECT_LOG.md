# PROJECT LOG — rezerv-gateway

> Хроника на всички branches/PR-и. Най-новите отгоре.
> Формат: `N. branch-name — обобщение`. Детайли: `docs/branches/<branch-name>.md`.

1. **feature/gateway-core** — Първоначален gateway: routing към cas/business/booking (StripPrefix на `/api`), HS256 JWT валидация с 401 в единния error формат, context headers (`X-User-Id`, `X-User-Roles`, `X-Company-Id`, `X-Correlation-Id`) + anti-spoofing, Redis rate limit per IP (20 req/s, burst 40), `companyId` claim coerce към string, 14 unit теста, Postman колекция. Детайли: `docs/branches/feature-gateway-core.md`.
