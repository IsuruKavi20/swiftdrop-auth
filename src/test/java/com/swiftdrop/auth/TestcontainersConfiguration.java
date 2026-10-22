package com.swiftdrop.auth;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * Starts the same Postgres image and runs the same role-creation script as docker-compose,
 * so tests use the least-privilege users: Flyway as identity_migrator, the app as identity_app.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

	private static final String MIGRATOR_PASSWORD = "test-migrator-password";
	private static final String APP_PASSWORD = "test-app-password";

	@Bean
	PostgreSQLContainer postgresContainer() {
		return new PostgreSQLContainer(DockerImageName.parse("postgres:17-alpine"))
				.withEnv("DB_MIGRATOR_PASSWORD", MIGRATOR_PASSWORD)
				.withEnv("DB_APP_PASSWORD", APP_PASSWORD)
				.withCopyFileToContainer(
						MountableFile.forHostPath("docker/postgres/init/01-roles.sh"),
						"/docker-entrypoint-initdb.d/01-roles.sh");
	}

	@Bean
	DynamicPropertyRegistrar databaseProperties(PostgreSQLContainer postgres) {
		return registry -> {
			registry.add("spring.datasource.url", postgres::getJdbcUrl);
			registry.add("spring.datasource.username", () -> "identity_app");
			registry.add("spring.datasource.password", () -> APP_PASSWORD);
			registry.add("spring.flyway.user", () -> "identity_migrator");
			registry.add("spring.flyway.password", () -> MIGRATOR_PASSWORD);
		};
	}

}
