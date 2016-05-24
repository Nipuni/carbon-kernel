package org.wso2.carbon.kernel.security.repository;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.security.SecretRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Created by nipuni on 5/19/16.
 */
public class FileBaseSecretRepository implements SecretRepository {

    private static Logger log = LoggerFactory.getLogger(FileBaseSecretRepository.class);

    private static final String LOCATION = "location";
    private static final String KEY_STORE = "keyStore";
    private static final String DOT = ".";
    private static final String SECRET = "secret";
    private static final String ALIAS = "alias";
    private static final String ALIASES = "aliases";
    private static final String ALGORITHM = "algorithm";
    private static final String DEFAULT_ALGORITHM = "RSA";
    private static final String TRUSTED = "trusted";
    private static final String DEFAULT_CONF_LOCATION = "cipher-text.properties";

    /* Parent secret repository */
    private SecretRepository parentRepository;
    /*Map of secrets keyed by alias for property name */
    private final Map<String, String> secrets = new HashMap<String, String>();
    /*Map of encrypted values keyed by alias for property name */
    private final Map<String, String> encryptedData = new HashMap<String, String>();
    /*Wrapper for Identity KeyStore */
//    private IdentityKeyStoreWrapper identity;
    /* Wrapper for trusted KeyStore */
//    private TrustKeyStoreWrapper trust;
    /* Whether this secret repository has been initiated successfully*/
    private boolean initialize = false;

//    public FileBaseSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
//        this.identity = identity;
//        this.trust = trust;
//    }

    /**
     * Initializes the repository based on provided properties
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    public void init(Properties properties, String id) {
        //todo
        //this will save secrets and encrypted values to "secrets" and "encryptedData" map against their alias
    }

    /**
     * @param alias Alias name for look up a secret
     * @return Secret if there is any , otherwise ,alias itself
     * @see org.wso2.carbon.kernel.security.SecretRepository
     */
    public String getSecret(String alias) {

        if (alias == null || "".equals(alias)) {
            return alias; // TODO is it needed to throw an error?
        }

        if (!initialize || secrets.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }

        StringBuffer sb = new StringBuffer();
        sb.append(alias);

        String secret = secrets.get(sb.toString());
        if (secret == null || "".equals(secret)) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }
        return secret;
    }


    /**
     * @param alias Alias name for look up a encrypted Value
     * @return encrypted Value if there is any , otherwise ,alias itself
     * @see org.wso2.carbon.kernel.security.SecretRepository
     */
    public String getEncryptedData(String alias) {

        if (alias == null || "".equals(alias)) {
            return alias; // TODO is it needed to throw an error?
        }

        if (!initialize || encryptedData.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }

        StringBuffer sb = new StringBuffer();
        sb.append(alias);

        String encryptedValue = encryptedData.get(sb.toString());
        if (encryptedValue == null || "".equals(encryptedValue)) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }
        return encryptedValue;
    }

    public void setParent(SecretRepository parent) {
        this.parentRepository = parent;
    }

    public SecretRepository getParent() {
        return this.parentRepository;
    }
}
