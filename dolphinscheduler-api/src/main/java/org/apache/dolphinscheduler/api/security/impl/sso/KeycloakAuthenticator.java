package org.apache.dolphinscheduler.api.security.impl.sso;

import org.apache.dolphinscheduler.api.security.impl.AbstractSsoAuthenticator;
import org.apache.dolphinscheduler.api.service.UsersService;
import org.apache.dolphinscheduler.common.constants.Constants;
import org.apache.dolphinscheduler.common.enums.UserType;
import org.apache.dolphinscheduler.dao.entity.User;
import org.apache.dolphinscheduler.dao.entity.Tenant;
import org.apache.dolphinscheduler.dao.mapper.TenantMapper;

import java.security.MessageDigest;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import lombok.NonNull;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakAuthenticator extends AbstractSsoAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthenticator.class);

    @Autowired
    private UsersService usersService;

    @Autowired
    private TenantMapper tenantMapper;

    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;
    @Value("${keycloak.realm}")
    private String keycloakRealm;
    @Value("${keycloak.resource}")
    private String clientId;
    @Value("${keycloak.credentials.secret}")
    private String clientSecret;
    @Value("${keycloak.redirect-uri}")
    private String redirectUri;
    @Value("${security.authentication.keycloak.user.admin:#{null}}")
    private String adminUserName;
    @Value("${security.authentication.keycloak.default.tenant:default}")
    private String defaultTenantCode;

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public User login(@NonNull String state, String code) {
        // state作为用户名，code作为密码传入
        // 1. 获取token
        String tokenEndpoint = String.format("%s/realms/%s/protocol/openid-connect/token", keycloakAuthServerUrl, keycloakRealm);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String body = "grant_type=authorization_code"
            + "&code=" + code
            + "&client_id=" + clientId
            + "&client_secret=" + clientSecret
            + "&redirect_uri=" + redirectUri;
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        
        try {
            ResponseEntity<Map> response = restTemplate.exchange(tokenEndpoint, HttpMethod.POST, entity, Map.class);
            if (!response.getStatusCode().is2xxSuccessful() || !response.getBody().containsKey("access_token")) {
                log.error("Failed to get access token from Keycloak");
                return null;
            }
            String accessToken = (String) response.getBody().get("access_token");
            String idToken = (String) response.getBody().get("id_token");
            ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (servletRequestAttributes != null && idToken != null) {
                HttpServletRequest request = servletRequestAttributes.getRequest();
                request.getSession().setAttribute("KEYCLOAK_ID_TOKEN", idToken);
            }

            // 2. 获取用户信息
            String userInfoEndpoint = String.format("%s/realms/%s/protocol/openid-connect/userinfo", keycloakAuthServerUrl, keycloakRealm);
            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userInfoEntity = new HttpEntity<>(userInfoHeaders);
            ResponseEntity<Map> userInfoResp = restTemplate.exchange(userInfoEndpoint, HttpMethod.GET, userInfoEntity, Map.class);
            if (!userInfoResp.getStatusCode().is2xxSuccessful()) {
                log.error("Failed to get user info from Keycloak");
                return null;
            }
            Map userInfo = userInfoResp.getBody();
            String userName = (String) userInfo.get("preferred_username");
            String email = (String) userInfo.get("email");
            if (userName == null) {
                log.error("No username found in Keycloak user info");
                return null;
            }
            
            // 3. 获取或创建本地用户
            User user = usersService.getUserByUserName(userName);
            if (user == null) {
                log.info("Creating new user from Keycloak: {}", userName);
                //user = usersService.createUser(getUserType(userName), userName, email);
                Tenant defaultTenant = tenantMapper.queryByTenantCode(defaultTenantCode);
                user = usersService.createUser(userName, null, email, defaultTenant.getId(), null, null, 1);
            }
            return user;
        } catch (Exception e) {
            log.error("Error during Keycloak authentication", e);
            return null;
        }
    }

    public UserType getUserType(String userName) {
        return adminUserName != null && adminUserName.equalsIgnoreCase(userName) ? UserType.ADMIN_USER
                : UserType.GENERAL_USER;
    }

    @Override
    public String getSignInUrl(String state) {
        // 拼接Keycloak登录URL
        log.info("Generating Keycloak sign-in URL with state: {}", state);
        return UriComponentsBuilder
                .fromHttpUrl(String.format("%s/realms/%s/protocol/openid-connect/auth", keycloakAuthServerUrl,
                        keycloakRealm))
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid email profile")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state)
                .build().toUriString();
    }

    @Override
    public String getLogoutUrl() {
        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        String idToken = null;
        if (servletRequestAttributes != null) {
            HttpServletRequest request = servletRequestAttributes.getRequest();
            Object tokenObj = request.getSession().getAttribute("KEYCLOAK_ID_TOKEN");
            if (tokenObj instanceof String) {
                idToken = (String) tokenObj;
            }
        }
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromHttpUrl(String.format("%s/realms/%s/protocol/openid-connect/logout", keycloakAuthServerUrl, keycloakRealm));
        if (idToken != null) {
            builder.queryParam("id_token_hint", idToken);
            builder.queryParam("post_logout_redirect_uri", redirectUri);
        }
        builder.queryParam("client_id", clientId);
        return builder.build().toUriString();
    }
}
