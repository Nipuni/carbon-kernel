package org.wso2.carbon.kernel.security.definition;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * Factory for creating KeyStoreInformation based on properties
 */
public class KeyStoreInformationFactory {

    private static Logger log = LoggerFactory.getLogger(KeyStoreInformationFactory.class);

    /* Private key entry KeyStore location */
    private final static String IDENTITY_KEY_STORE = "keystore.identity.location";
    /* Private key entry KeyStore type  */
    private final static String IDENTITY_KEY_STORE_TYPE = "keystore.identity.type";
    /* Alias for private key entry KeyStore */
    private final static String IDENTITY_KEY_STORE_ALIAS = "keystore.identity.alias";
    /* Password for access keyStore*/
    private final static String IDENTITY_KEY_STORE_PASSWORD = "keystore.identity.store";
    /* Password for get private key*/
    private final static String IDENTITY_KEY_PASSWORD = "keystore.identity.key";

    private final static String KEY_STORE_PARAMETERS = "keystore.identity.parameters";

    /* Trusted certificate KeyStore location */
    private final static String TRUST_STORE = "keystore.trust.location";
    /* Trusted certificate KeyStore type*/
    private final static String TRUST_STORE_TYPE = "keystore.trust.type";
    /* Alias for certificate KeyStore */
    private final static String TRUST_STORE_ALIAS = "keystore.trust.alias";
    /* Password for access TrustStore*/
    private final static String TRUST_STORE_PASSWORD = "keystore.trust.store";

    private final static String TRUST_STORE_PARAMETERS = "keystore.trust.parameters";
    /* Dot string */
    private final static String DOT = ".";
    /* Prompt for trust store password*/
    private final static String TRUSTSTORE_PASSWORD_PROMPT = "Trust Store Password > ";
    /* Prompt for identity store password*/
    private final static String IDENTITYSTORE_PASSWORD_PROMPT = "Identity Store Password > ";
    /* Prompt for identity store private key password*/
    private final static String IDENTITYSTORE_PRIVATE_KEY_PASSWORD_PROMPT
            = "Identity Store Private Key Password > ";

    /**
     * Creates a KeyStoreInformation using synapse properties
     * Uses KeyStore configuration properties
     *
     * @param properties Synapse Properties
     * @return IdentityKeyStoreInformation instance
     */
    public static IdentityKeyStoreInformation createIdentityKeyStoreInformation(Properties properties) {

        String keyStoreLocation = properties.getProperty(IDENTITY_KEY_STORE);
        if (keyStoreLocation == null || "".equals(keyStoreLocation)) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a KeyStoreLocation for private key store");
            }
            return null;
        }

        IdentityKeyStoreInformation keyStoreInformation = new IdentityKeyStoreInformation();
        keyStoreInformation.setAlias(
                properties.getProperty(IDENTITY_KEY_STORE_ALIAS));
        keyStoreInformation.setLocation(keyStoreLocation);
        keyStoreInformation.setStoreType(
                properties.getProperty(IDENTITY_KEY_STORE_TYPE));

        keyStoreInformation.setKeyStorePasswordProvider(
                SecretInformationFactory.createSecretInformation(properties,
                        IDENTITY_KEY_STORE_PASSWORD + DOT,
                        IDENTITYSTORE_PASSWORD_PROMPT));

        keyStoreInformation.setKeyPasswordProvider(
                SecretInformationFactory.createSecretInformation(
                        properties, IDENTITY_KEY_PASSWORD + DOT,
                        IDENTITYSTORE_PRIVATE_KEY_PASSWORD_PROMPT));

        String parameterString = MiscellaneousUtil.getProperty(
                properties, KEY_STORE_PARAMETERS, null);

        //Adds optional parameters
        parseParameter(parameterString, keyStoreInformation);
        return keyStoreInformation;
    }

    /**
     * Creates a TrustKeyStoreInformation using synapse properties
     * Uses TrustStore Configuration properties
     *
     * @param properties Synapse Properties
     * @return TrustKeyStoreInformation instance
     */
    public static TrustKeyStoreInformation createTrustKeyStoreInformation(Properties properties) {

        String keyStoreLocation =
                MiscellaneousUtil.getProperty(properties,
                        TRUST_STORE, null);
        if (keyStoreLocation == null || "".equals(keyStoreLocation)) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a KeyStoreLocation for trust store");
            }
            return null;
        }

        TrustKeyStoreInformation trustInformation = new TrustKeyStoreInformation();
        trustInformation.setAlias(
                MiscellaneousUtil.getProperty(properties, TRUST_STORE_ALIAS, null));
        trustInformation.setLocation(keyStoreLocation);
        trustInformation.setStoreType(
                MiscellaneousUtil.getProperty(properties,
                        TRUST_STORE_TYPE, null));

        trustInformation.setKeyStorePasswordProvider(
                SecretInformationFactory.createSecretInformation(
                        properties, TRUST_STORE_PASSWORD + DOT, TRUSTSTORE_PASSWORD_PROMPT));

        String parameterString = MiscellaneousUtil.getProperty(
                properties, TRUST_STORE_PARAMETERS, null);

        //Adds optional parameters
        parseParameter(parameterString, trustInformation);
        return trustInformation;
    }

    /**
     * Helper method to parse parameter values (String ) and add those to KeyStoreInformation
     *
     * @param parameterString Parameter String
     * @param information     KeyStoreInformation
     */
    private static void parseParameter(String parameterString, KeyStoreInformation information) {

        if (parameterString == null || "".equals(parameterString)) {
            if (log.isDebugEnabled()) {
                log.debug("No additional parameter for KeyStore");
            }
            return;
        }

        String[] parameterPairs = parameterString.split(";");
        if (parameterPairs == null) {
            if (log.isDebugEnabled()) {
                log.debug("No additional parameter for KeyStore");
            }
            return;
        }

        for (String parameterPairString : parameterPairs) {
            String[] values = parameterPairString.split("=");
            if (values == null || values.length != 2) {
                if (log.isDebugEnabled()) {
                    log.debug("A parameter with no (name,value) pair has been found ");
                }
                return;
            }
            information.addParameter(values[0], values[1]);
        }
    }
}
