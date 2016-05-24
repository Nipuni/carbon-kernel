package org.wso2.carbon.kernel.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.security.definition.IdentityKeyStoreInformation;
import org.wso2.carbon.kernel.security.definition.KeyStoreInformationFactory;
import org.wso2.carbon.kernel.security.definition.TrustKeyStoreInformation;

import java.util.Properties;

/**
 * Created by nipuni on 5/19/16. //todo
 */
public class SecretManager {

    private static Logger log = LoggerFactory.getLogger(SecretManager.class);

    private final static SecretManager SECRET_MANAGER = new SecretManager();

    /* Default configuration file path for secret manager*/
    private final static String PROP_DEFAULT_CONF_LOCATION = "secret-manager.properties";
    /* If the location of the secret manager configuration is provided as a property- it's name */
    private final static String PROP_SECRET_MANAGER_CONF = "secret.manager.conf";
    /* Property key for secretRepositories*/
    private final static String PROP_SECRET_REPOSITORIES = "secretRepositories";
    /* Type of the secret repository */
    private final static String PROP_PROVIDER = "provider";
    /* Dot string */
    private final static String DOT = ".";

    /*Root Secret Repository */
    private SecretRepository parentRepository;
    /* True , if secret manage has been started up properly- need to have a at
    least one Secret Repository*/
    private boolean initialized = false;

    // global password provider implementation class if defined in secret manager conf file
    private String globalSecretProvider =null;
    // property key for global secret provider
    private final static String PROP_SECRET_PROVIDER="carbon.secretProvider";

    public static SecretManager getInstance() {
        return SECRET_MANAGER;
    }

    private SecretManager() {
    }

    /**
     * Initializes the Secret Manager by providing configuration properties
     *
     * @param properties Configuration properties
     */
    public void init(Properties properties) { //todo call this method when reading serverConfiguration from carbon.yml

        if (initialized) {
            if (log.isDebugEnabled()) {
                log.debug("Secret Manager already has been started.");
            }
            return;
        }

        if (properties == null) {
            if (log.isDebugEnabled()) {
                log.debug("KeyStore configuration properties cannot be found");
            }
            return;
        }

        globalSecretProvider = MiscellaneousUtil.getProperty(properties, PROP_SECRET_PROVIDER,null);
        if(globalSecretProvider==null || "".equals(globalSecretProvider)){
            if(log.isDebugEnabled()){
                log.debug("No global secret provider is configured.");
            }
        }

        String repositoriesString = MiscellaneousUtil.getProperty(
                properties, PROP_SECRET_REPOSITORIES, null);       //todo usage (we set this from ciphertool)
        if (repositoriesString == null || "".equals(repositoriesString)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return;
        }

        String[] repositories = repositoriesString.split(",");
        if (repositories == null || repositories.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return;
        }

        //Create a KeyStore Information  for private key entry KeyStore
        IdentityKeyStoreInformation identityInformation =
                KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);

        // Create a KeyStore Information for trusted certificate KeyStore
        TrustKeyStoreInformation trustInformation =
                KeyStoreInformationFactory.createTrustKeyStoreInformation(properties);

        String identityKeyPass = null;
        String identityStorePass = null;
        String trustStorePass = null;
        if(identityInformation != null){
            identityKeyPass = identityInformation
                    .getKeyPasswordProvider().getResolvedSecret();
            identityStorePass = identityInformation
                    .getKeyStorePasswordProvider().getResolvedSecret();
        }

        if(trustInformation != null){
            trustStorePass = trustInformation
                    .getKeyStorePasswordProvider().getResolvedSecret();
        }


        if (!validatePasswords(identityStorePass, identityKeyPass, trustStorePass)) {
            if (log.isDebugEnabled()) {
                log.info("Either Identity or Trust keystore password is mandatory" +
                        " in order to initialized secret manager.");
            }
            return;
        }

        IdentityKeyStoreWrapper identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
        identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

        TrustKeyStoreWrapper trustKeyStoreWrapper = new TrustKeyStoreWrapper();
        if(trustInformation != null){
            trustKeyStoreWrapper.init(trustInformation);
        }


        SecretRepository currentParent = null;
        for (String secretRepo : repositories) {

            StringBuffer sb = new StringBuffer();
            sb.append(PROP_SECRET_REPOSITORIES);
            sb.append(DOT);
            sb.append(secretRepo);
            String id = sb.toString();
            sb.append(DOT);
            sb.append(PROP_PROVIDER);

            String provider = MiscellaneousUtil.getProperty(
                    properties, sb.toString(), null);
            if (provider == null || "".equals(provider)) {
                handleException("Repository provider cannot be null ");
            }

            if (log.isDebugEnabled()) {
                log.debug("Initiating a File Based Secret Repository");
            }

            try {

                Class aClass = getClass().getClassLoader().loadClass(provider.trim());
                Object instance = aClass.newInstance();

                if (instance instanceof SecretRepositoryProvider) {
                    SecretRepository secretRepository = ((SecretRepositoryProvider) instance).
                            getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
                    secretRepository.init(properties, id);
                    if (parentRepository == null) {
                        parentRepository = secretRepository;
                    }
                    secretRepository.setParent(currentParent);
                    currentParent = secretRepository;
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully Initiate a Secret Repository provided by : "
                                + provider);
                    }
                } else {
                    handleException("Invalid class as SecretRepositoryProvider : Class Name : "
                            + provider);
                }

            } catch (ClassNotFoundException e) {
                handleException("A Secret Provider cannot be found for class name : " + provider);
            } catch (IllegalAccessException e) {
                handleException("Error creating a instance from class : " + provider);
            } catch (InstantiationException e) {
                handleException("Error creating a instance from class : " + provider);
            }
        }

    }

    public boolean isInitialized() {
        return initialized;
    }

    private static void handleException(String msg) {
        log.error(msg);
        throw new RuntimeException(msg);  //todo
    }
}
