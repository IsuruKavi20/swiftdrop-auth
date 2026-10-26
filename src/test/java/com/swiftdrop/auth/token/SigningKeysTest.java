package com.swiftdrop.auth.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningKeysTest {

    @TempDir
    Path folder;

    @Test
    void generatesA3072BitRs256SigningKeyWithTheConfiguredId() {
        RSAKey key = SigningKeys.generate("auth-test");

        assertThat(key.size()).isEqualTo(3072);
        assertThat(key.getKeyID()).isEqualTo("auth-test");
        assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(key.isPrivate()).isTrue();
    }

    @Test
    void savedKeyIsLoadedBackIdentically() throws Exception {
        Path file = folder.resolve("nested/jwt-signing-key.pem");
        RSAKey created = SigningKeys.loadOrCreate(file, "auth-test", true);

        RSAKey loaded = SigningKeys.loadOrCreate(file, "auth-test", false);

        assertThat(Files.readString(file)).startsWith("-----BEGIN PRIVATE KEY-----");
        assertThat(loaded.toRSAPublicKey()).isEqualTo(created.toRSAPublicKey());
        assertThat(loaded.toRSAPrivateKey()).isEqualTo(created.toRSAPrivateKey());
    }

    @Test
    void createdKeyFileIsOwnerOnlyWhereTheFileSystemSupportsIt() throws Exception {
        Path file = folder.resolve("owner-only.pem");
        SigningKeys.loadOrCreate(file, "auth-test", true);

        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertThat(java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(file)))
                    .isEqualTo("rw-------");
        }
        try (var leftovers = Files.list(folder)) {
            assertThat(leftovers.map(Path::getFileName).map(Path::toString)).noneMatch(name -> name.endsWith(".tmp"));
        }
    }

    @Test
    void missingKeyFailsWhenCreatingIsNotAllowed() {
        assertThatThrownBy(() -> SigningKeys.loadOrCreate(folder.resolve("absent.pem"), "auth-test", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("absent.pem");
    }

    @Test
    void keysWeakerThan2048BitsAreRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        Path file = folder.resolve("weak.pem");
        SigningKeys.writePem(file, generator.generateKeyPair().getPrivate());

        assertThatThrownBy(() -> SigningKeys.loadOrCreate(file, "auth-test", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("2048");
    }
}
