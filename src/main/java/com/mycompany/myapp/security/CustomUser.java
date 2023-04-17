package com.mycompany.myapp.security;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class CustomUser extends User {

    private final String accountId;

    public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String accountId) {
        super(username, password, authorities);
        this.accountId = accountId;
    }
}
