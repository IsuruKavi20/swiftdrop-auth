package com.swiftdrop.auth.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import jakarta.persistence.Entity;
import org.junit.jupiter.api.Test;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.data.repository.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RestController;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;
import static com.tngtech.archunit.library.GeneralCodingRules.NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS;
import static com.tngtech.archunit.library.GeneralCodingRules.NO_CLASSES_SHOULD_USE_FIELD_INJECTION;
import static com.tngtech.archunit.library.GeneralCodingRules.NO_CLASSES_SHOULD_USE_JAVA_UTIL_LOGGING;

/** The structure rules of this project, enforced on every build. */
class ArchitectureTest {

    private static final String BASE = "com.swiftdrop.auth";

    private final JavaClasses production = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages(BASE);

    @Test
    void controllersLiveOnlyInApiPackages() {
        // One deliberate exception: the replacement for Spring Boot's /error page is infrastructure, not a feature API
        classes().that().areAnnotatedWith(RestController.class)
                .and().doNotImplement(ErrorController.class)
                .should().resideInAPackage("..api..")
                .check(production);
    }

    @Test
    void webLayerNeverTouchesEntitiesOrRepositories() {
        noClasses().that().resideInAPackage("..api..")
                .should().dependOnClassesThat().areAnnotatedWith(Entity.class)
                .orShould().dependOnClassesThat().areAssignableTo(Repository.class)
                .because("controllers speak DTOs only; entities and repositories stay behind the service layer")
                .check(production);
    }

    @Test
    void dtosAreImmutableRecords() {
        classes().that().resideInAPackage("..api.dto..")
                .should().beRecords()
                .check(production);
    }

    @Test
    void transactionsAreNeverStartedInTheWebLayer() {
        noClasses().that().resideInAPackage("..api..")
                .should().beAnnotatedWith(Transactional.class)
                .check(production);
        noMethods().that().areDeclaredInClassesThat().resideInAPackage("..api..")
                .should().beAnnotatedWith(Transactional.class)
                .check(production);
    }

    @Test
    void sharedCodeDependsOnNoFeature() {
        noClasses().that().resideInAPackage(BASE + ".common..")
                .should().dependOnClassesThat().resideInAnyPackage(
                        BASE + ".signup..", BASE + ".user..", BASE + ".verification..", BASE + ".security..")
                .check(production);
    }

    @Test
    void generalCodingRules() {
        NO_CLASSES_SHOULD_USE_FIELD_INJECTION.check(production);
        NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS.check(production);
        NO_CLASSES_SHOULD_USE_JAVA_UTIL_LOGGING.check(production);
    }
}
