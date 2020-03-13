package software.amazon.awssdk.crt.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static java.time.temporal.ChronoUnit.DAYS;

/**
 * A {@code TemporaryKeystoreFactory} can produce valid self signed, public/private key in the JKS format. This is not a
 * suitable method of obtaining a JKS file for production, but for small purely internal services and testing, this a
 * great tool.
 */
final class TemporaryKeystoreFactory {

    private static final String CERT_TEMPLATE = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----";

    public static void newKeystore(File keystorePath, String password) {
        if (keystorePath.exists()) {
            if (!isKeystoreUsable(keystorePath, password)) {
                if (!keystorePath.delete()) {
                    throw new RuntimeException("Could not delete keystore path " + keystorePath.getAbsolutePath());
                }
            } else {
                return;
            }
        }
        createKeystore(keystorePath, password);
    }

    public static String newSelfSignedCAPem() {
        try {
            final KeyPair pair = genEcdsaKeyPair();
            final X509Certificate cert = generateCertificate(pair, "SHA384WithECDSA");

            return String.format(CERT_TEMPLATE, Base64.getMimeEncoder()
                    .encodeToString(cert.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a temporary Keystore
     */
    private static void createKeystore(File file, String password) {
        try {

            if (!file.getParentFile().mkdirs() && !file.getParentFile().isDirectory()) {
                throw new IllegalStateException(
                        "Could not create directory " + file.getParentFile().getAbsolutePath()
                                + " for temporary keystore");
            }

            KeyStore store = generateKeyStore(password);
            try (FileOutputStream out = new FileOutputStream(file)) {
                store.store(out, password.toCharArray());
            }
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    public static KeyStore generateKeyStore(String password) {
        try {
            String storeType = KeyStore.getDefaultType();
            KeyStore store = KeyStore.getInstance(storeType);

            store.load(null, password.toCharArray());
            addKey(store, genRsaKeyPair(), "rsa-key", "SHA256WithRSA", password);
            addKey(store, genEcdsaKeyPair(), "ecdsa-key", "SHA384WithECDSA", password);

            return store;
        } catch (GeneralSecurityException | IOException t) {
            throw new RuntimeException(t);
        }
    }

    private static void addKey(KeyStore store, KeyPair keyPair, String alias, String signingAlgorithm, String password) throws GeneralSecurityException {
        store.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(),
                new X509Certificate[]{ generateCertificate(keyPair, signingAlgorithm) });
    }

    private static KeyPair genRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static KeyPair genEcdsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp384r1"));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Given a Keystore file, try and load it to verify we have the correct password and that the file's not corrupt
     */
    private static boolean isKeystoreUsable(File file, String password) {
        if (!file.exists()) {
            return false;
        }

        try {

            String storeType = KeyStore.getDefaultType();
            KeyStore store = KeyStore.getInstance(storeType);

            try (FileInputStream in = new FileInputStream(file)) {
                store.load(in, password.toCharArray());
            }

            return true;
        } catch (Throwable t) {
            // Password mismatch, keystore corrupt
        }

        return false;
    }

    /**
     * Generates a self-signed certificate using Bouncy Castle
     * @param keyPair key to sign certificate
     * @return a self-signed X509 Certificate
     * @throws CertificateException if a certificate could not be generated
     */
    private static X509Certificate generateCertificate(final KeyPair keyPair, String signingAlgorithm) throws CertificateException {
        final String cn = "Amazon.com";
        final String o = "Amazon.com";
        final String ou = "Amazon.com";
        final String city = "Seattle";
        final String state = "WA";
        final String country = "US";
        final X500Name x500Name = new X500Name(
                String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", cn, ou, o, city, state, country));

        final Instant now = Instant.now();
        final Date notBefore =  Date.from(now);
        final Date notAfter = Date.from(now.plus(90, DAYS));
        final BigInteger serial = new BigInteger(64, new SecureRandom());

        final JcaX509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(x500Name, serial, notBefore, notAfter, x500Name, keyPair.getPublic());

        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signingAlgorithm);
        final ContentSigner signer;
        try {
            signer = signerBuilder.build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new CertificateException(e);
        }

        final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        return certificateConverter.getCertificate(certificateBuilder.build(signer));
    }
}