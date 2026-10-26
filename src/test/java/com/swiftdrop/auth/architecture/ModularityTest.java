package com.swiftdrop.auth.architecture;

import com.swiftdrop.auth.AuthApplication;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;

/**
 * Each direct sub-package of com.swiftdrop.auth is a module. This fails the build if modules form a
 * cycle, or if one module reaches into another module's internal (non-exposed) packages.
 */
class ModularityTest {

    private final ApplicationModules modules = ApplicationModules.of(AuthApplication.class);

    @Test
    void modulesHaveNoCyclesAndUseOnlyEachOthersPublicApi() {
        modules.verify();
    }

}
