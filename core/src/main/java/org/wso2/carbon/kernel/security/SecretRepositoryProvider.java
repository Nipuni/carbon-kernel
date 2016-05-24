package org.wso2.carbon.kernel.security;

/**
 * Created by nipuni on 5/19/16.    //todo
 */
public interface SecretRepositoryProvider {

    /**
     * Returns a SecretRepository implementation
     *
     * @param identity Identity KeyStore
     * @param trust    Trust KeyStore
     * @return A SecretRepository implementation
     */
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust);
}
