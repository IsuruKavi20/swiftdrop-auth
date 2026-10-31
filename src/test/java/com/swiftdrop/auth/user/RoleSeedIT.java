package com.swiftdrop.auth.user;

import com.swiftdrop.auth.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class RoleSeedIT {

    @Autowired
    private RoleRepository roleRepository;

    @Test
    void everyRoleNameInJavaExistsInTheDatabase() {
        assertThat(Arrays.stream(RoleName.values()))
                .allSatisfy(name -> assertThat(roleRepository.findByName(name)).isPresent());
    }

    @Test
    void databaseHasNoRolesUnknownToJava() {
        assertThat(roleRepository.findAll())
                .extracting(Role::getName)
                .containsExactlyInAnyOrder(RoleName.values());
    }
}
