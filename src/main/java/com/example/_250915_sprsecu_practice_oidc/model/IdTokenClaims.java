package com.example._250915_sprsecu_practice_oidc.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
public class IdTokenClaims {
    // Essential Claim
    private String issuer;       // iss
    private String subject;      // sub
    private String audience;     // aud
    private Instant expiresAt;   // exp
    private Instant issuedAt;    // iat
    private Instant authTime;    // auth_time
    // Profile Claim
    private String name;
    private String givenName;
    private String familyName;
    private String middleName;
    private String nickname;
    private String preferredUsername;
    private String profile;
    private String picture;
    private String website;
    private String gender;
    private String birthdate;
    private String zoneinfo;
    private String locale;
    private Instant updatedAt;
    // Email Claim
    private String email;
    private Boolean emailVerified;
    // Address Claim
    private Map<String, Object> address;
    // Overall Claim
    private Map<String, Object> allClaims;
    // ID Token Value
    private String tokenValue;
    // Convenient Method
    public String getDisplayName() {
        if (name != null) return name;
        if (givenName != null && familyName != null) {
            return givenName + " " + familyName;
        }
        return preferredUsername != null ? preferredUsername : subject;
    }
    public String getProfileImage() {
        return picture != null ? picture : "/images/default-profile.png";
    }
    public boolean isTokenExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }
}
