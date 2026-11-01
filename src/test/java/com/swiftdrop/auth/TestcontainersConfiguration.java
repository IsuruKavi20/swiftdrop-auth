package com.swiftdrop.auth;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * Starts the same Postgres image and runs the same role-creation script as docker-compose,
 * so tests use the least-privilege users: Flyway as identity_migrator, the app as identity_app.
 * Also starts Mailpit, a fake mail server whose inbox tests can read over its REST API,
 * and Redis with a password, like production (shared rate limits and the Google login session).
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

	private static final String MIGRATOR_PASSWORD = "test-migrator-password";
	private static final String APP_PASSWORD = "test-app-password";
	private static final int SMTP_PORT = 1025;
	private static final int MAILPIT_API_PORT = 8025;
	public static final String REDIS_IMAGE = "redis:7.4-alpine";
	public static final String REDIS_PASSWORD = "test-redis-password";
	public static final int REDIS_PORT = 6379;

	/** Redis that, like production, refuses every command until the client sends the password. */
	public static GenericContainer<?> newRedisContainer() {
		return new GenericContainer<>(DockerImageName.parse(REDIS_IMAGE))
				.withCommand("redis-server", "--requirepass", REDIS_PASSWORD)
				.withExposedPorts(REDIS_PORT)
				.waitingFor(Wait.forLogMessage(".*Ready to accept connections.*\n", 1));
	}

	/** Postgres with the same least-privilege roles as docker-compose. */
	public static PostgreSQLContainer newPostgresContainer() {
		return new PostgreSQLContainer(DockerImageName.parse("postgres:17-alpine"))
				.withEnv("DB_MIGRATOR_PASSWORD", MIGRATOR_PASSWORD)
				.withEnv("DB_APP_PASSWORD", APP_PASSWORD)
				.withCopyFileToContainer(
						MountableFile.forHostPath("docker/postgres/init/01-roles.sh"),
						"/docker-entrypoint-initdb.d/01-roles.sh");
	}

	/** The connection settings the app needs for these containers (also used to start extra instances). */
	public static java.util.Map<String, Object> connectionProperties(PostgreSQLContainer postgres, GenericContainer<?> redis) {
		return java.util.Map.of(
				"spring.datasource.url", postgres.getJdbcUrl(),
				"spring.datasource.username", "identity_app",
				"spring.datasource.password", APP_PASSWORD,
				"spring.flyway.user", "identity_migrator",
				"spring.flyway.password", MIGRATOR_PASSWORD,
				"spring.data.redis.host", redis.getHost(),
				"spring.data.redis.port", redis.getMappedPort(REDIS_PORT),
				"spring.data.redis.password", REDIS_PASSWORD);
	}

	@Bean
	PostgreSQLContainer postgresContainer() {
		return newPostgresContainer();
	}

	@Bean
	GenericContainer<?> redisContainer() {
		return newRedisContainer();
	}

	@Bean
	GenericContainer<?> mailpitContainer() {
		return new GenericContainer<>(DockerImageName.parse("axllent/mailpit:v1.31.5"))
				.withExposedPorts(SMTP_PORT, MAILPIT_API_PORT)
				.waitingFor(Wait.forHttp("/api/v1/info").forPort(MAILPIT_API_PORT));
	}

	@Bean
	MailpitClient mailpitClient(GenericContainer<?> mailpitContainer) {
		return new MailpitClient("http://" + mailpitContainer.getHost() + ":"
				+ mailpitContainer.getMappedPort(MAILPIT_API_PORT));
	}

	@Bean
	DynamicPropertyRegistrar databaseProperties(PostgreSQLContainer postgres, GenericContainer<?> mailpitContainer,
												GenericContainer<?> redisContainer) {
		return registry -> {
			connectionProperties(postgres, redisContainer).forEach((name, value) -> registry.add(name, () -> value));
			registry.add("spring.mail.host", mailpitContainer::getHost);
			registry.add("spring.mail.port", () -> mailpitContainer.getMappedPort(SMTP_PORT));
		};
	}

}
