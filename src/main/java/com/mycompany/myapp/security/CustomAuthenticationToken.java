package com.mycompany.myapp.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class CustomAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private Object someValue;

    public CustomAuthenticationToken(Object principal, Object credentials, Object someValue) {
        super(principal, credentials);
        this.someValue = someValue;
    }
}
