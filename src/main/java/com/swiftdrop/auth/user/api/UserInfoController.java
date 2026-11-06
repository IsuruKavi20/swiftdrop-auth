package com.swiftdrop.auth.user.api;

import com.swiftdrop.auth.security.CurrentUser;
import com.swiftdrop.auth.user.ProfileService;
import com.swiftdrop.auth.user.api.dto.ProfileResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * OpenID Connect UserInfo (OIDC Core 5.3; identity step 4c): the standard "who is this access token for". The
 * same claims and rules as GET /me/profile (active accounts only, user tokens only); GET and POST as the spec asks.
 */
@RestController
public class UserInfoController {

    public static final String PATH = "/oauth2/userinfo";

    private final ProfileService profiles;

    UserInfoController(ProfileService profiles) {
        this.profiles = profiles;
    }

    @RequestMapping(value = PATH, method = {RequestMethod.GET, RequestMethod.POST},
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ProfileResponse> userInfo(@AuthenticationPrincipal Jwt token) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(ProfileResponse.from(profiles.get(CurrentUser.idOf(token))));
    }
}
