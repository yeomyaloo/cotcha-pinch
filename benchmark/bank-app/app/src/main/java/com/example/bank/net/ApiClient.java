package com.example.bank.net;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;

public class ApiClient {

    public OkHttpClient create() throws GeneralSecurityException {
        SSLContext ssl = SSLContext.getInstance("TLS");
        TrustAllManager trustAll = new TrustAllManager();
        ssl.init(null, new TrustManager[]{trustAll}, new SecureRandom());
        return new OkHttpClient.Builder().sslSocketFactory(ssl.getSocketFactory(), trustAll).build();
    }

    static class TrustAllManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static class PinningTrustManager implements X509TrustManager {

        private final X509TrustManager system;
        private final String pin;

        PinningTrustManager(X509TrustManager system, String pin) {
            this.system = system;
            this.pin = pin;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            system.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            system.checkServerTrusted(chain, authType);
            if (!pin.equals(fingerprint(chain[0]))) {
                throw new CertificateException("pin mismatch");
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return system.getAcceptedIssuers();
        }

        private static String fingerprint(X509Certificate certificate) throws CertificateException {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(certificate.getPublicKey().getEncoded());
                return new String(Base64.getEncoder().encode(hash), StandardCharsets.US_ASCII);
            } catch (GeneralSecurityException e) {
                throw new CertificateException(e);
            }
        }
    }
}
