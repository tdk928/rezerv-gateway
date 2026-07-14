package bg.rezerv.gateway.config;

/** Context headers, които gateway закача към forward-натите заявки (REZERV.md §2.3). */
public final class HeaderNames {

    public static final String X_USER_ID = "X-User-Id";
    public static final String X_USER_ROLES = "X-User-Roles";
    public static final String X_COMPANY_ID = "X-Company-Id";
    public static final String X_CORRELATION_ID = "X-Correlation-Id";

    private HeaderNames() {
    }
}
