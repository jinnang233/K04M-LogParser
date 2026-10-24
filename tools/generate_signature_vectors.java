// Regenerates tests/data/signature-vectors.json.
//
// This developer-only tool uses the reference Krypt04Mcg implementation and
// Bouncy Castle 1.86 to produce signed packets for every signature suite the
// Rust verifier supports. The private keys are throwaway test material.
//
// Usage (from the K04M-LogParser repository):
//
//   BC_JAR=/path/to/Krypt04Mcg/build/processIncludeJars/bcprov-jdk18on-1.86.jar
//   GSON_JAR=$(find ~/.gradle/caches -name 'gson-2.14.0.jar' | head -1)
//   KRYPT_CLASSES=/path/to/Krypt04Mcg/build/classes/java/main
//   javac -cp "$KRYPT_CLASSES:$BC_JAR:$GSON_JAR" -d /tmp/k04m-signature-vectors \
//       tools/generate_signature_vectors.java
//   java -cp "/tmp/k04m-signature-vectors:$KRYPT_CLASSES:$BC_JAR:$GSON_JAR" \
//       GenSignatureVectors > tests/data/signature-vectors.json

import com.google.gson.Gson;
import dev.krypt04mcg.config.AeadAlgorithm;
import dev.krypt04mcg.config.KemAlgorithm;
import dev.krypt04mcg.config.SignatureAlgorithm;
import dev.krypt04mcg.crypto.CryptoService;
import dev.krypt04mcg.model.AlgorithmSuite;
import dev.krypt04mcg.model.EncryptedPacket;
import dev.krypt04mcg.model.LocalKeyMaterial;
import dev.krypt04mcg.model.PacketType;
import dev.krypt04mcg.model.PublicIdentity;
import dev.krypt04mcg.protocol.PacketCodec;

import java.util.Base64;

class GenSignatureVectors {
    static final Gson GSON = new Gson();

    static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static void emit(StringBuilder out, boolean first, String name,
                     SignatureAlgorithm algorithm, LocalKeyMaterial sender,
                     PublicIdentity receiver, String plaintext) throws Exception {
        CryptoService crypto = new CryptoService();
        PublicIdentity senderIdentity = new PublicIdentity(
                sender.kemPublicKey().owner(), sender.kemPublicKey().uuid(),
                sender.kemPublicKey(), sender.signaturePublicKey());
        EncryptedPacket packet = crypto.encryptFor(receiver, sender,
                sender.kemPublicKey().owner(), plaintext, true, false,
                AeadAlgorithm.AES_256_GCM);
        PacketCodec codec = new PacketCodec();
        out.append(first ? "" : ",").append("{\n")
                .append("\"name\":\"").append(name).append("\",\n")
                .append("\"signature_algorithm\":\"").append(algorithm.identifier()).append("\",\n")
                .append("\"sender_identity\":").append(GSON.toJson(senderIdentity)).append(",\n")
                .append("\"expected_plaintext\":\"").append(plaintext).append("\",\n")
                .append("\"packet_base64url\":\"").append(b64(codec.encode(packet))).append("\",\n")
                .append("\"aad_hex\":\"").append(java.util.HexFormat.of().formatHex(codec.aadFor(packet))).append("\"\n")
                .append("}");
    }

    static void emitLegacyV1(StringBuilder out, boolean first, LocalKeyMaterial sender,
                             PublicIdentity receiver, SignatureAlgorithm algorithm) throws Exception {
        CryptoService crypto = new CryptoService();
        PacketCodec codec = new PacketCodec();
        byte[] messageId = new byte[16];
        for (int i = 0; i < messageId.length; i++) messageId[i] = (byte) (0x40 + i);
        byte[] nonce = new byte[12];
        for (int i = 0; i < nonce.length; i++) nonce[i] = (byte) (0x10 + i);
        byte[] kemCiphertext = new byte[32];
        for (int i = 0; i < kemCiphertext.length; i++) kemCiphertext[i] = (byte) (0x20 + i);
        byte[] ciphertext = new byte[20];
        for (int i = 0; i < ciphertext.length; i++) ciphertext[i] = (byte) (0x30 + i);
        AlgorithmSuite suite = AlgorithmSuite.of(KemAlgorithm.ML_KEM_768_X25519,
                algorithm, AeadAlgorithm.AES_256_GCM);
        EncryptedPacket unsigned = new EncryptedPacket((byte) 1, PacketType.SIGNED_KEM_MESSAGE,
                (byte) 0x01, sender.kemPublicKey().owner(), receiver.owner(),
                1_700_000_000_000L, messageId, (short) 0, (short) 1, suite,
                nonce, kemCiphertext, ciphertext, new byte[0]);
        byte[] signature = crypto.sign(sender.signaturePrivateKey(), codec.signatureInput(unsigned));
        EncryptedPacket signed = new EncryptedPacket((byte) 1, PacketType.SIGNED_KEM_MESSAGE,
                (byte) 0x01, sender.kemPublicKey().owner(), receiver.owner(),
                1_700_000_000_000L, messageId, (short) 0, (short) 1, suite,
                nonce, kemCiphertext, ciphertext, signature);
        PublicIdentity identity = new PublicIdentity(sender.kemPublicKey().owner(),
                sender.kemPublicKey().uuid(), sender.kemPublicKey(), sender.signaturePublicKey());
        out.append(first ? "" : ",").append("{\n")
                .append("\"name\":\"legacy_v1_ml_dsa_65\",\n")
                .append("\"signature_algorithm\":\"").append(algorithm.identifier()).append("\",\n")
                .append("\"sender_identity\":").append(GSON.toJson(identity)).append(",\n")
                .append("\"expected_plaintext\":\"\",\n")
                .append("\"packet_base64url\":\"").append(b64(codec.encode(signed))).append("\",\n")
                .append("\"aad_hex\":\"").append(java.util.HexFormat.of().formatHex(codec.aadFor(signed))).append("\"\n")
                .append("}");
    }

    public static void main(String[] args) throws Exception {
        CryptoService crypto = new CryptoService();
        LocalKeyMaterial bob = crypto.generateLocalKeys("bob", "uuid-bob",
                KemAlgorithm.ML_KEM_768_X25519, SignatureAlgorithm.MLDSA65_ED25519_SHA512);
        PublicIdentity bobId = new PublicIdentity("bob", "uuid-bob",
                bob.kemPublicKey(), bob.signaturePublicKey());

        StringBuilder out = new StringBuilder();
        out.append("{\n\"tool\":\"bouncycastle-1.86\",\n\"cases\":[\n");
        boolean first = true;

        // Native Bouncy Castle composite signatures (the Krypt04Mcg default).
        record Case(String name, SignatureAlgorithm algorithm, String plaintext) {}
        Case[] nativeComposite = new Case[] {
                new Case("composite_mldsa44_ed25519", SignatureAlgorithm.MLDSA44_ED25519_SHA512, "composite 44"),
                new Case("composite_mldsa65_ed25519", SignatureAlgorithm.MLDSA65_ED25519_SHA512, "composite 65"),
                new Case("composite_mldsa87_ed448", SignatureAlgorithm.MLDSA87_ED448_SHAKE256, "composite 87"),
        };
        for (Case testCase : nativeComposite) {
            LocalKeyMaterial sender = crypto.generateLocalKeys("alice",
                    "uuid-" + testCase.name(), KemAlgorithm.ML_KEM_768_X25519, testCase.algorithm());
            emit(out, first, testCase.name(), testCase.algorithm(), sender, bobId, testCase.plaintext());
            first = false;
        }

        // Standalone FIPS 204 / FIPS 205 suites.
        Case[] standalone = new Case[] {
                new Case("standalone_ml_dsa_65", SignatureAlgorithm.ML_DSA_65, "standalone mldsa"),
                new Case("standalone_slh_dsa_sha2_128f", SignatureAlgorithm.SLH_DSA_SHA2_128F, "standalone slhdsa"),
        };
        for (Case testCase : standalone) {
            LocalKeyMaterial sender = crypto.generateLocalKeys("alice",
                    "uuid-" + testCase.name(), KemAlgorithm.ML_KEM_768_X25519, testCase.algorithm());
            emit(out, first, testCase.name(), testCase.algorithm(), sender, bobId, testCase.plaintext());
            first = false;
        }

        // Legacy protocol v1 packet: the timestamp is signed but not part of
        // the AEAD AAD, so it specifically exercises PacketCodec.signatureInput.
        LocalKeyMaterial legacy = crypto.generateLocalKeys("alice", "uuid-legacy",
                KemAlgorithm.ML_KEM_768_X25519, SignatureAlgorithm.ML_DSA_65);
        emitLegacyV1(out, first, legacy, bobId, SignatureAlgorithm.ML_DSA_65);
        first = false;

        // Project custom K04-HYBRID-SIGNATURE-V1 frames.
        Case[] customHybrid = new Case[] {
                new Case("custom_ml_dsa_65_ed25519", SignatureAlgorithm.ML_DSA_65_ED25519, "custom hybrid 65"),
                new Case("custom_ml_dsa_87_ed448", SignatureAlgorithm.ML_DSA_87_ED448, "custom hybrid 87"),
                new Case("custom_slh_dsa_sha2_128f_ed25519", SignatureAlgorithm.SLH_DSA_SHA2_128F_ED25519, "custom hybrid slh"),
        };
        for (Case testCase : customHybrid) {
            LocalKeyMaterial sender = crypto.generateLocalKeys("alice",
                    "uuid-" + testCase.name(), KemAlgorithm.ML_KEM_768_X25519, testCase.algorithm());
            emit(out, first, testCase.name(), testCase.algorithm(), sender, bobId, testCase.plaintext());
            first = false;
        }

        out.append("\n]\n}\n");
        System.out.print(out);
    }
}
