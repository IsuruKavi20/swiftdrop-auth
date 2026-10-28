package com.swiftdrop.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** One specific allowed action, e.g. "parcel:assign". Seeded by Flyway (V6); roles hold sets of them. */
@Entity
@Table(name = "permissions")
public class Permission {

    @Id
    private Short id;

    @Column(nullable = false, unique = true, length = 60)
    private String name;

    protected Permission() {
        // required by JPA
    }

    public String getName() {
        return name;
    }
}
