package com.example._250915_sprsecu_practice_oidc.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {
    private final IdTokenService idTokenService;
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String clientId = userRequest.getClientRegistration().getClientId();
        log.info("OIDC 사용자 로드 시작: 제공자={}, 사용자={}", registrationId, oidcUser.getName());
        try {
            boolean isValid = idTokenService.validateIdToken(oidcUser.getIdToken(), clientId);
            if (!isValid) {
                throw new OAuth2AuthenticationException("ID Token 검증 실패");
            }
            // Email Verification Check (if it is needed)
            idTokenService.analyzedIdTokenClaims(oidcUser.getIdToken());
            log.info("OIDC 사용자 처리 완료: 제공자={}, 사용자ID={}, 이름={}, 이메일={}",
                    registrationId, oidcUser.getSubject(), oidcUser.getName(), oidcUser.getEmail());
            return oidcUser;
        } catch (Exception e) {
            log.error("OIDC 사용자 처리 중 오류 발생: 제공자={}, 오류={}", registrationId, e.getMessage(), e);
            throw new OAuth2AuthenticationException("OIDC 사용자 처리 실패: " + e.getMessage());
        }
    }
}
