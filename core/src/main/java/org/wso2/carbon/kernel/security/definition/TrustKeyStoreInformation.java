package org.wso2.carbon.kernel.security.definition;

import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;

/**
 * Represents the abstraction - Trusted Certificate Store Information
 */
public class TrustKeyStoreInformation extends KeyStoreInformation {

    /**
     * Returns the TrustManagerFactory instance
     *
     * @return TrustManagerFactory instance
     */
    public TrustManagerFactory getTrustManagerFactoryInstance() {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Creating a TrustManagerFactory instance");
            }
            KeyStore trustStore = this.getTrustStore();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            return trustManagerFactory;
        } catch (Exception e) {
            handleException("Error getting TrustManagerFactory: ", e);
        }

        return null;
    }

    /**
     * Returns a KeyStore instance that has been created using trust store
     *
     * @return KeyStore Instance
     */
    public KeyStore getTrustStore() {
        return super.getKeyStore();

    }

}

