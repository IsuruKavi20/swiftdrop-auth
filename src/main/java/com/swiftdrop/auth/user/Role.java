package com.swiftdrop.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "roles")
public class Role {

    public static final String CUSTOMER = "CUSTOMER";

    @Id
    private Short id;

    @Column(nullable = false, unique = true, length = 30)
    private String name;

    protected Role() {
        // required by JPA
    }

    public Short getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
