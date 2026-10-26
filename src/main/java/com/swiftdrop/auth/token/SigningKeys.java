package com.swiftdrop.auth.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Creates, saves and loads the RSA key that signs access tokens. The private key stays on this server;
 * only its public half will be published (JWKS, Step 8). Keys below 2048 bits are refused.
 */
final class SigningKeys {

    static final int GENERATED_KEY_BITS = 3072;
    private static final int MIN_KEY_BITS = 2048;
    private static final String BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String END = "-----END PRIVATE KEY-----";

    private SigningKeys() {
    }

    static RSAKey generate(String keyId) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(GENERATED_KEY_BITS);
            KeyPair pair = generator.generateKeyPair();
            return toJwk((RSAPublicKey) pair.getPublic(), (RSAPrivateCrtKey) pair.getPrivate(), keyId);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not generate an RSA signing key", e);
        }
    }

    /** Loads the key from a PEM file; if it doesn't exist and {@code create} is true, generates and saves one. */
    static RSAKey loadOrCreate(Path file, String keyId, boolean create) {
        if (Files.exists(file)) {
            return load(file, keyId);
        }
        if (!create) {
            throw new IllegalStateException("JWT signing key not found: " + file.toAbsolutePath());
        }
        RSAKey key = generate(keyId);
        try {
            writePem(file, key.toPrivateKey());
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new IllegalStateException("Could not save the generated JWT signing key", e);
        }
        return key;
    }

    static void writePem(Path file, PrivateKey privateKey) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(privateKey.getEncoded());
        try {
            Path folder = file.toAbsolutePath().getParent();
            Files.createDirectories(folder);
            // Write to a temporary file first, then rename: a crash can't leave a half-written key behind
            Path temporary = Files.createTempFile(folder, ".jwt-key-", ".tmp");
            restrictToOwner(temporary);
            Files.writeString(temporary, BEGIN + "\n" + body + "\n" + END + "\n", StandardCharsets.US_ASCII);
            Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new IllegalStateException("Could not write the JWT signing key to " + file.toAbsolutePath(), e);
        }
    }

    // rw------- where the file system supports it (Linux/macOS). On Windows the file inherits the user
    // profile's permissions; production keys come from a mounted secret, not from this method.
    private static void restrictToOwner(Path file) throws IOException {
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
    }

    private static RSAKey load(Path file, String keyId) {
        try {
            String pem = Files.readString(file, StandardCharsets.US_ASCII);
            String base64 = pem.replace(BEGIN, "").replace(END, "").replaceAll("\\s", "");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
            if (privateKey.getModulus().bitLength() < MIN_KEY_BITS) {
                throw new IllegalStateException("JWT signing key must be at least " + MIN_KEY_BITS + " bits");
            }
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            return toJwk(publicKey, privateKey, keyId);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
            throw new IllegalStateException("Could not read the JWT signing key " + file.toAbsolutePath()
                    + " (expected an unencrypted PKCS#8 RSA private key in PEM format)", e);
        }
    }

    private static RSAKey toJwk(RSAPublicKey publicKey, RSAPrivateCrtKey privateKey, String keyId) {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }
}
