// Regenerates tests/data/decryption-vectors.json.
//
// This developer-only tool uses the reference Krypt04Mcg implementation and
// Bouncy Castle 1.86 to produce real ciphertexts. The generated JSON contains
// throwaway private keys used solely by the Rust decryption tests; never use
// these keys for real traffic.
//
// Usage (from the K04M-LogParser repository):
//
//   BC_JAR=/path/to/Krypt04Mcg/build/processIncludeJars/bcprov-jdk18on-1.86.jar
//   GSON_JAR=$(find ~/.gradle/caches -name 'gson-2.14.0.jar' | head -1)
//   KRYPT_CLASSES=/path/to/Krypt04Mcg/build/classes/java/main
//   javac -cp "$KRYPT_CLASSES:$BC_JAR:$GSON_JAR" -d /tmp/k04m-vectors \
//       tools/generate_decryption_vectors.java
//   java -cp "/tmp/k04m-vectors:$KRYPT_CLASSES:$BC_JAR:$GSON_JAR" \
//       GenVectors > tests/data/decryption-vectors.json
//
// The reference project must be built first (./gradlew classes).

import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.KeyRecord;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class GenVectors {
    static final SecureRandom RANDOM = new SecureRandom();

    static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String esc(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    static String keyJson(KeyRecord key) {
        return "{\"algorithm\":\"" + esc(key.algorithm()) + "\",\"owner\":\"" + esc(key.owner())
                + "\",\"uuid\":\"" + esc(key.uuid()) + "\",\"fingerprint\":\""
                + esc(key.fingerprint()) + "\",\"createdAt\":\"" + key.createdAt()
                + "\",\"keyData\":\"" + esc(key.keyData()) + "\"}";
    }

    static String materialJson(LocalKeyMaterial material) {
        return "{\"kemPublicKey\":" + keyJson(material.kemPublicKey())
                + ",\"kemPrivateKey\":" + keyJson(material.kemPrivateKey())
                + ",\"signaturePublicKey\":" + keyJson(material.signaturePublicKey())
                + ",\"signaturePrivateKey\":" + keyJson(material.signaturePrivateKey()) + "}";
    }

    static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(String.format("%02x", value));
        }
        return text.toString();
    }

    static String packetJson(EncryptedPacket packet) {
        PacketCodec codec = new PacketCodec();
        return "\"packet_base64url\":\"" + b64(codec.encode(packet)) + "\",\"aad_hex\":\""
                + hex(codec.aadFor(packet)) + "\",\"ciphered\":true}";
    }

    static void writeEncrypted(Path root, Path file, byte[] masterKey, String plaintext)
            throws Exception {
        Files.createDirectories(file.getParent());
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] aad = root.relativize(file).toString().replace('\\', '/')
                .getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey, "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] envelope = new byte[8 + 12 + ciphertext.length];
        System.arraycopy("KMCGSEC1".getBytes(StandardCharsets.US_ASCII), 0, envelope, 0, 8);
        System.arraycopy(nonce, 0, envelope, 8, 12);
        System.arraycopy(ciphertext, 0, envelope, 20, ciphertext.length);
        Files.write(file, envelope);
    }

    public static void main(String[] args) throws Exception {
        CryptoService crypto = new CryptoService();
        StringBuilder out = new StringBuilder();
        out.append("{\n\"tool\":\"bouncycastle-1.86\",\n\"cases\":[\n");
        boolean first = true;

        LocalKeyMaterial alice = crypto.generateLocalKeys("alice", "uuid-alice");
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "uuid-bob");
        PublicIdentity bobId = new PublicIdentity("bob", "uuid-bob",
                bob.kemPublicKey(), bob.signaturePublicKey());
        PublicIdentity aliceId = new PublicIdentity("alice", "uuid-alice",
                alice.kemPublicKey(), alice.signaturePublicKey());

        // ML-KEM-768+X25519 native composite, AES-256-GCM, compressed.
        EncryptedPacket defaultPacket = crypto.encryptFor(bobId, alice, "alice",
                "hello from alice 你好", false, true, AeadAlgorithm.AES_256_GCM);
        out.append(first ? "" : ",").append("{\"name\":\"kem_default_mlkem768_x25519_aesgcm_compressed\",")
                .append("\"kem_algorithm\":\"").append(esc(defaultPacket.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(defaultPacket.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(alice)).append(",")
                .append("\"receiver_key\":").append(materialJson(bob)).append(",")
                .append("\"expected_plaintext\":\"hello from alice 你好\",")
                .append(packetJson(defaultPacket));
        first = false;

        // Native composite with ChaCha20-Poly1305, uncompressed.
        EncryptedPacket chachaPacket = crypto.encryptFor(aliceId, bob, "bob",
                "chacha plain", false, false, AeadAlgorithm.CHACHA20_POLY1305);
        out.append(",{\"name\":\"kem_default_mlkem768_x25519_chacha_uncompressed\",")
                .append("\"kem_algorithm\":\"").append(esc(chachaPacket.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(chachaPacket.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(bob)).append(",")
                .append("\"receiver_key\":").append(materialJson(alice)).append(",")
                .append("\"expected_plaintext\":\"chacha plain\",")
                .append(packetJson(chachaPacket));

        // Custom K04-HYBRID-V1 ML-KEM-512 + X25519.
        LocalKeyMaterial carol = crypto.generateLocalKeys("carol", "uuid-carol",
                KemAlgorithm.ML_KEM_512_X25519, SignatureAlgorithm.MLDSA65_ED25519_SHA512);
        PublicIdentity carolId = new PublicIdentity("carol", "uuid-carol",
                carol.kemPublicKey(), carol.signaturePublicKey());
        EncryptedPacket hybrid512 = crypto.encryptFor(carolId, alice, "alice",
                "custom hybrid 512", false, true, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"kem_custom_mlkem512_x25519\",")
                .append("\"kem_algorithm\":\"").append(esc(hybrid512.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(hybrid512.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(alice)).append(",")
                .append("\"receiver_key\":").append(materialJson(carol)).append(",")
                .append("\"expected_plaintext\":\"custom hybrid 512\",")
                .append(packetJson(hybrid512));

        // Bare ML-KEM-768.
        LocalKeyMaterial dave = crypto.generateLocalKeys("dave", "uuid-dave",
                KemAlgorithm.ML_KEM_768, SignatureAlgorithm.MLDSA65_ED25519_SHA512);
        PublicIdentity daveId = new PublicIdentity("dave", "uuid-dave",
                dave.kemPublicKey(), dave.signaturePublicKey());
        EncryptedPacket bare768 = crypto.encryptFor(daveId, bob, "bob",
                "bare mlkem 768", false, false, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"kem_bare_mlkem768\",")
                .append("\"kem_algorithm\":\"").append(esc(bare768.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(bare768.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(bob)).append(",")
                .append("\"receiver_key\":").append(materialJson(dave)).append(",")
                .append("\"expected_plaintext\":\"bare mlkem 768\",")
                .append(packetJson(bare768));

        // Custom K04-HYBRID-V1 ML-KEM-1024 + X25519.
        LocalKeyMaterial erin = crypto.generateLocalKeys("erin", "uuid-erin",
                KemAlgorithm.ML_KEM_1024_X25519, SignatureAlgorithm.MLDSA65_ED25519_SHA512);
        PublicIdentity erinId = new PublicIdentity("erin", "uuid-erin",
                erin.kemPublicKey(), erin.signaturePublicKey());
        EncryptedPacket hybrid1024 = crypto.encryptFor(erinId, alice, "alice",
                "custom hybrid 1024", false, true, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"kem_custom_mlkem1024_x25519\",")
                .append("\"kem_algorithm\":\"").append(esc(hybrid1024.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(hybrid1024.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(alice)).append(",")
                .append("\"receiver_key\":").append(materialJson(erin)).append(",")
                .append("\"expected_plaintext\":\"custom hybrid 1024\",")
                .append(packetJson(hybrid1024));

        // Native ML-KEM-1024+X448 composite (category-5 preset).
        LocalKeyMaterial frank = crypto.generateLocalKeys("frank", "uuid-frank",
                KemAlgorithm.ML_KEM_1024_X448, SignatureAlgorithm.MLDSA87_ED448_SHAKE256);
        PublicIdentity frankId = new PublicIdentity("frank", "uuid-frank",
                frank.kemPublicKey(), frank.signaturePublicKey());
        EncryptedPacket nativeX448 = crypto.encryptFor(frankId, alice, "alice",
                "native mlkem1024 x448", false, true, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"kem_native_mlkem1024_x448\",")
                .append("\"kem_algorithm\":\"").append(esc(nativeX448.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(nativeX448.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(alice)).append(",")
                .append("\"receiver_key\":").append(materialJson(frank)).append(",")
                .append("\"expected_plaintext\":\"native mlkem1024 x448\",")
                .append(packetJson(nativeX448));

        // Custom K04-HYBRID-V1 ML-KEM-512 + X448.
        LocalKeyMaterial grace = crypto.generateLocalKeys("grace", "uuid-grace",
                KemAlgorithm.ML_KEM_512_X448, SignatureAlgorithm.MLDSA87_ED448_SHAKE256);
        PublicIdentity graceId = new PublicIdentity("grace", "uuid-grace",
                grace.kemPublicKey(), grace.signaturePublicKey());
        EncryptedPacket hybrid512X448 = crypto.encryptFor(graceId, bob, "bob",
                "custom mlkem512 x448", false, false, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"kem_custom_mlkem512_x448\",")
                .append("\"kem_algorithm\":\"").append(esc(hybrid512X448.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(hybrid512X448.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(bob)).append(",")
                .append("\"receiver_key\":").append(materialJson(grace)).append(",")
                .append("\"expected_plaintext\":\"custom mlkem512 x448\",")
                .append(packetJson(hybrid512X448));

        // Session message.
        byte[] secret = new byte[32];
        RANDOM.nextBytes(secret);
        byte[] sessionIdBytes = new byte[16];
        RANDOM.nextBytes(sessionIdBytes);
        String sessionId = b64(sessionIdBytes);
        String sessionPayload = "{\"version\":2,\"message\":\"secret session text 会话内容\"}";
        EncryptedPacket sessionPacket = crypto.encryptWithSession("bob", "alice", secret,
                sessionId, 7L, sessionPayload, true, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"session_aesgcm_compressed\",")
                .append("\"session_secret\":\"").append(b64(secret)).append("\",")
                .append("\"session_id\":\"").append(sessionId).append("\",")
                .append("\"session_owner\":\"alice\",\"session_peer\":\"bob\",")
                .append("\"expected_plaintext\":\"").append(esc(sessionPayload)).append("\",")
                .append(packetJson(sessionPacket));

        // Signed exchange request, decryptable with bob's long-term key.
        String exchangePayload = "{\"version\":2,\"kind\":\"REQUEST\",\"initiator\":\"alice\","
                + "\"initiatorUuid\":\"uuid-alice\",\"responder\":\"bob\",\"responderUuid\":\"uuid-bob\","
                + "\"sessionId\":\"" + sessionId + "\",\"requestMessageId\":\"\","
                + "\"initiatorFingerprint\":\"aa\",\"responderFingerprint\":\"bb\","
                + "\"ephemeralKem\":\"ML-KEM-768+X25519\",\"ephemeralPublicKey\":\"\","
                + "\"sessionSecret\":\"\",\"createdAtMillis\":123,\"previousSessionId\":\"\","
                + "\"requestEpoch\":0}";
        EncryptedPacket exchangePacket = crypto.encryptSessionExchange(bob.kemPublicKey(), "bob",
                alice, "alice", exchangePayload, false, false, AeadAlgorithm.AES_256_GCM);
        out.append(",{\"name\":\"session_exchange_request\",")
                .append("\"kem_algorithm\":\"").append(esc(exchangePacket.algorithms().kem())).append("\",")
                .append("\"aead\":\"").append(esc(exchangePacket.algorithms().aead())).append("\",")
                .append("\"sender_key\":").append(materialJson(alice)).append(",")
                .append("\"receiver_key\":").append(materialJson(bob)).append(",")
                .append("\"expected_plaintext\":\"").append(esc(exchangePayload)).append("\",")
                .append(packetJson(exchangePacket));

        // Encrypted account storage (KMCGSEC1) fixture.
        byte[] masterKey = new byte[32];
        RANDOM.nextBytes(masterKey);
        Path account = Files.createTempDirectory("k04m-vectors-account-");
        Files.createDirectories(account.resolve("secrets"));
        byte[] masterFile = new byte[8 + 1 + 32];
        System.arraycopy("KMCGKEY1".getBytes(StandardCharsets.US_ASCII), 0, masterFile, 0, 8);
        masterFile[8] = 2;
        System.arraycopy(masterKey, 0, masterFile, 9, 32);
        Files.write(account.resolve("secrets/master.key"), masterFile);
        writeEncrypted(account, account.resolve("keys/private/local.json"), masterKey,
                materialJson(bob));
        String sessionRecord = "{\"peer\":\"bob\",\"peerFingerprint\":\"bb\",\"sessionId\":\""
                + sessionId + "\",\"createdAt\":\"2026-10-22T00:00:00Z\","
                + "\"lastUsedAt\":\"2026-10-22T00:00:00Z\",\"secret\":\"" + b64(secret)
                + "\",\"messageCount\":0,\"bytesUsed\":0,\"nextSendSequence\":0,"
                + "\"nextReceiveSequence\":0}";
        writeEncrypted(account, account.resolve("sessions/bob.json"), masterKey, sessionRecord);
        out.append("],\n\"encrypted_account\":{\n")
                .append("\"key_file_packet\":\"").append(b64(new PacketCodec().encode(defaultPacket))).append("\",\n")
                .append("\"session_file_packet\":\"").append(b64(new PacketCodec().encode(sessionPacket))).append("\",\n")
                .append("\"expected_key_plaintext\":\"hello from alice 你好\",\n")
                .append("\"expected_session_plaintext\":\"").append(esc(sessionPayload)).append("\",\n")
                .append("\"files\":{\n")
                .append("\"secrets/master.key\":\"").append(b64(masterFile)).append("\",\n")
                .append("\"keys/private/local.json\":\"")
                .append(b64(Files.readAllBytes(account.resolve("keys/private/local.json")))).append("\",\n")
                .append("\"sessions/bob.json\":\"")
                .append(b64(Files.readAllBytes(account.resolve("sessions/bob.json")))).append("\"\n")
                .append("}}}\n");

        for (Path path : Files.walk(account).sorted(java.util.Comparator.reverseOrder()).toList()) {
            Files.deleteIfExists(path);
        }
        System.out.print(out);
    }
}
