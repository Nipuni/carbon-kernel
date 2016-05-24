package org.wso2.carbon.kernel.security.definition;

import javax.net.ssl.KeyManagerFactory;
import java.security.KeyStore;

/**
 * Represents the abstraction private key entry store (identity) information
 */
public class IdentityKeyStoreInformation extends KeyStoreInformation {

    /* Password for access private key*/
    private SecretInformation keyPasswordProvider;

    public void setKeyPasswordProvider(SecretInformation keyPasswordProvider) {
        this.keyPasswordProvider = keyPasswordProvider;
    }

    /**
     * Returns the IdentityKeyManagerFactory instance
     *
     * @return IdentityKeyManagerFactory instance
     */
    public KeyManagerFactory getIdentityKeyManagerFactoryInstance() {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Creating a IdentityKeyManagerFactory instance");
            }

            KeyStore keyStore = this.getIdentityKeyStore();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPasswordProvider.getResolvedSecret().toCharArray());

            return keyManagerFactory;
        } catch (Exception e) {
            handleException("Error getting KeyManagerFactory: ", e);
        }

        return null;
    }

    /**
     * Returns a KeyStore instance that has been created from identity keystore
     *
     * @return KeyStore Instance
     */
    public KeyStore getIdentityKeyStore() {
        return super.getKeyStore();
    }

    public SecretInformation getKeyPasswordProvider() {
        return keyPasswordProvider;
    }
}

