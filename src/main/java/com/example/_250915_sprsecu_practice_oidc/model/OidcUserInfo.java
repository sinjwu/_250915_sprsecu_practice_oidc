package com.example._250915_sprsecu_practice_oidc.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class OidcUserInfo {
    private String provider;
    private Instant loginTime;
    // Info extracted from ID Token
    private IdTokenClaims idTokenClaims;
    // Additional Info extracted from UserInfo
    private Map<String, Object> userInfoClaims;
    // Integrated User Info
    private String userId;
    private String name;
    private String email;
    private String picture;
    private Boolean emailVerified;
    public static OidcUserInfo from(String provider, OidcUser oidcUser) {
        return OidcUserInfo.builder()
                .provider(provider)
                .loginTime(Instant.now())
                .idTokenClaims(extractIdTokenClaims(oidcUser))
                .userInfoClaims(extractUserInfoClaims(oidcUser))
                .userId(oidcUser.getSubject())
                .name(oidcUser.getEmail())
                .picture(oidcUser.getPicture())
                .emailVerified(oidcUser.getEmailVerified())
                .build();
    }
    private static IdTokenClaims extractIdTokenClaims(OidcUser oidcUser) {
        var idToken = oidcUser.getIdToken();
        var claims = idToken.getClaims();
        return IdTokenClaims.builder()
                .issuer(idToken.getIssuer().toString())
                .subject(idToken.getSubject())
                .audience(idToken.getAudience().toString())
                .expiresAt(idToken.getExpiresAt())
                .issuedAt(idToken.getIssuedAt())
                .authTime(idToken.getAuthenticatedAt())
                .name((String) claims.get("name"))
                .givenName((String) claims.get("given_name"))
                .familyName((String) claims.get("family_name"))
                .email((String) claims.get("email"))
                .emailVerified((Boolean) claims.get("email_verified"))
                .picture((String) claims.get("picture"))
                .locale((String) claims.get("locale"))
                .allClaims(claims)
                .tokenValue(idToken.getTokenValue())
                .build();

    }
    private static Map<String, Object> extractUserInfoClaims(OidcUser oidcUser) {
        org.springframework.security.oauth2.core.oidc.OidcUserInfo userInfo = oidcUser.getUserInfo();
        return userInfo != null ? userInfo.getClaims() : null;
    }
}
