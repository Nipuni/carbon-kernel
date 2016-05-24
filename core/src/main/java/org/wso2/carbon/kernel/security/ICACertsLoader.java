package org.wso2.carbon.kernel.security;

import java.security.KeyStore;

/**
 * ICACertsLoader provides an uniform interface to create a keyStore containing CA certs
 * (trust store)
 */
public interface ICACertsLoader {
    /**
     * @param CACertificateFilesPath Path to the CA certificates directory
     * @return KeyStore Instance
     */
    public abstract KeyStore loadTrustStore(String CACertificateFilesPath);
}
