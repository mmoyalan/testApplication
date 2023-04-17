package com.mycompany.myapp.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class CustomAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private Object details;

    public CustomAuthenticationToken(Object principal, Object credentials, Object details) {
        super(principal, credentials);
        this.details = details;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public void setDetails(Object details) {
        this.details = details;
    }
}
