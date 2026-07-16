package bg.rezerv.gateway.security;

import java.util.List;

/** Claims, които gateway чете от валиден access token (REZERV.md §2.2). */
public record JwtClaims(String userId, String email, List<String> roles, String companyId) {

    public String rolesAsHeader() {
        return String.join(",", roles);
    }
}
