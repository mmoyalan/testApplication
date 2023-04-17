package com.mycompany.myapp.web.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mycompany.myapp.security.CustomAuthenticationToken;
import com.mycompany.myapp.security.SecurityUtils;
import com.mycompany.myapp.security.jwt.CustomTokenProvider;
import com.mycompany.myapp.security.jwt.JWTFilter;
import com.mycompany.myapp.security.jwt.TokenProvider;
import com.mycompany.myapp.web.rest.vm.LoginVM;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class UserJWTController {

    private final CustomTokenProvider tokenProvider;

    private final AuthenticationManager authenticationManager;

    public UserJWTController(CustomTokenProvider tokenProvider, AuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authorize(
        @Valid @RequestBody LoginVM loginVM,
        @RequestHeader(value = "Source", required = false) String someSource
    ) {
        UsernamePasswordAuthenticationToken authenticationToken;
        if (someSource != null && someSource.equals("some source")) {
            Map<String, String> details = new HashMap<>();
            details.put("someSource", someSource);
            authenticationToken = new CustomAuthenticationToken(loginVM.getUsername(), loginVM.getPassword(), details);
        } else {
            authenticationToken = new UsernamePasswordAuthenticationToken(loginVM.getUsername(), loginVM.getPassword());
        }

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.createToken(authentication, loginVM.isRememberMe());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
    }

    /**
     * Object to return as body in JWT Authentication.
     */
    static class JWTToken {

        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        @JsonProperty("id_token")
        String getIdToken() {
            return idToken;
        }

        void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
