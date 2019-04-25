package com.easycodebox.oauth.client.controller;

import com.easycodebox.common.security.AuthUser;
import java.security.Principal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author WangXiaoJin
 * @date 2019-03-14 16:12
 */
@RestController
public class TestController {

    @Autowired
    private UserInfoRestTemplateFactory templateFactory;

    @GetMapping("/user")
    @Secured("ROLE_USER")
    public Principal user(Principal principal) {
        AuthUser user = ((AuthUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        System.out.println(user);
        return principal;
    }

    @GetMapping("/user1")
    @PreAuthorize("hasRole('USER')")
    public String user1(@AuthenticationPrincipal(expression = "username") String username) {
        return username;
    }

    @GetMapping("/user2")
    @PreAuthorize("hasRole('USER')")
    public String user2(@AuthenticationPrincipal(expression = "realname") String realname) {
        return realname;
    }

    @GetMapping("/permit")
    @PreAuthorize("permitAll()")
    public String permit() {
        return "CLIENT - permit : " + DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(LocalDateTime.now());
    }

    @GetMapping("/deny")
    @PreAuthorize("denyAll()")
    public String deny() {
        return "CLIENT - deny : " + DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(LocalDateTime.now());
    }

    @GetMapping("/server-permit")
    public String serverPermit() {
        OAuth2RestTemplate userInfoRestTemplate = templateFactory.getUserInfoRestTemplate();
        return userInfoRestTemplate.getForObject("http://oauth.easycodebox.local:7500/permit", String.class);
    }

    @GetMapping("/res-permit")
    public String resPermit() {
        OAuth2RestTemplate userInfoRestTemplate = templateFactory.getUserInfoRestTemplate();
        return userInfoRestTemplate.getForObject("http://localhost:7510/permit", String.class);
    }

    @GetMapping("/res-deny")
    public String resDeny() {
        OAuth2RestTemplate userInfoRestTemplate = templateFactory.getUserInfoRestTemplate();
        return userInfoRestTemplate.getForObject("http://localhost:7510/deny", String.class);
    }

    @GetMapping("/res-user")
    public String resUser() {
        return templateFactory.getUserInfoRestTemplate().getForObject("http://localhost:7510/user", String.class);
    }

    @GetMapping("/res-time-active-refresh-token")
    public String resTimeActiveRefreshToken() {
        OAuth2RestTemplate userInfoRestTemplate = templateFactory.getUserInfoRestTemplate();
        //设置AccessTokenProviderChain，激活RefreshToken功能。
        // 如果真的想激活此功能，不要直接调用setAccessTokenProvider，参考DefaultUserInfoRestTemplateFactory.getUserInfoRestTemplate()方法。
        userInfoRestTemplate.setAccessTokenProvider(new AccessTokenProviderChain(Arrays.asList(
            new AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
            new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider())));
        return userInfoRestTemplate.getForObject("http://localhost:7510/test", String.class);
    }

}
