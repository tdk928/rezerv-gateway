# rezerv-gateway

Единствената публична входна точка на REZERV платформата (виж `../REZERV.md` — single source of truth).

- **Порт:** 8080
- **Стек:** Java 21, Spring Boot, Spring Cloud Gateway (WebFlux)
- **Отговорности:** JWT валидация, отхвърляне на неавторизирани заявки, rate limit (Redis), routing към вътрешните сервизи, закачане на context headers (`X-User-Id`, `X-User-Roles`, `X-Company-Id`, `X-Correlation-Id`).

## Стартиране локално

Изисква вдигната инфраструктура от [rezerv-infra](https://github.com/tdk928/rezerv-infra) (Redis на порт 6380):

```bash
mvn spring-boot:run
```

## Routing

| Префикс | Сервиз | Auth |
|---------|--------|------|
| `/api/auth/**` | rezerv-cas :8081 | `register`, `login`, `refresh` — публични |
| `/api/business/public/**` | rezerv-business :8082 | Публично |
| `/api/business/**` | rezerv-business :8082 | JWT |
| `/api/bookings/public/**` | rezerv-booking :8083 | Публично |
| `/api/bookings/**` | rezerv-booking :8083 | JWT |

Gateway маха `/api` префикса при forward (StripPrefix).

## Документация

- `docs/PROJECT_LOG.md` — хроника на всички branches/PR-и.
- `docs/branches/` — детайлно описание на всеки branch.
- `postman/` — Postman колекция за ръчно тестване.
