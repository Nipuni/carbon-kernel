package org.wso2.carbon.kernel.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Constructs a keyStore from CA certificates
 */
public class CACertsLoader implements ICACertsLoader {

    private static Logger log = LoggerFactory.getLogger(CACertsLoader.class);

    /**
     * Constructs a keyStore from the path provided.
     *
     * @param CACertificateFilesPath - directory which contains Certificate Authority
     *                               Certificates in PEM encoding.
     */
    public KeyStore loadTrustStore(String CACertificateFilesPath) {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Creating KeyStore from given CA certificates" +
                        " in the given directory : " + CACertificateFilesPath);
            }

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);

            File certsPath = new File(CACertificateFilesPath);

            File[] certs = certsPath.listFiles();

            for (File currentCert : certs) {
                FileInputStream inStream = new FileInputStream(currentCert);
                BufferedInputStream bis = new BufferedInputStream(inStream);

                CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                Certificate cert = certFactory.generateCertificate(bis);

                trustStore.setCertificateEntry(currentCert.getName(), cert);

                bis.close();
                inStream.close();
            }

            return trustStore;
        } catch (IOException e) {
            handleException("IOError when reading certificates from " +
                    "directory : " + CACertificateFilesPath, e);
        } catch (NoSuchAlgorithmException e) {
            handleException("Error creating a KeyStore", e);
        } catch (KeyStoreException e) {
            handleException("Error creating a KeyStore", e);
        } catch (CertificateException e) {
            handleException("Error creating a KeyStore", e);
        }
        return null;
    }

    private void handleException(String msg, Exception e) {
        log.error(msg, e);
        throw new RuntimeException(msg, e);
    }
}
