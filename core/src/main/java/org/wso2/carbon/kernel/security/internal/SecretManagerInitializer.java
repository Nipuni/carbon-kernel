package org.wso2.carbon.kernel.security.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.security.SecretCallbackHandler;
import org.wso2.carbon.kernel.security.SecretManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Created by nipuni on 5/19/16.
 */
public class SecretManagerInitializer {
//todo this internal module is seperate from securevault and should remain inside carbon

    private SecretManager secretManager = SecretManager.getInstance();
    private static final Logger log = LoggerFactory.getLogger(SecretManagerInitializer.class);
    public static final String CARBON_HOME = "carbon.home";
    private String SECRET_CONF = "secret-vault.yml";
    private static String CONF_DIR = "conf";
    private static final String SECURITY_DIR = "security";
    private static String GLOBAL_PREFIX = "carbon.";

    public SecretCallbackHandler init() { //todo return  SecretCallbackHandlerServiceImpl

        Properties properties = new Properties();

        if (secretManager.isInitialized()) {
            if (log.isDebugEnabled()) {
                log.debug("SecretManager already has been initialized.");
            }
        } else {
            properties = loadProperties();
            secretManager.init(properties);
        }

        SecretCallbackHandler serviceImpl = null;

        if (!secretManager.isInitialized()) {

            System.out.println("Secret manager initialized");

//            SecretCallbackHandler passwordProvider =
//                    SecretCallbackHandlerFactory.createSecretCallbackHandler(properties,
//                            GLOBAL_PREFIX + SecurityConstants.PASSWORD_PROVIDER_SIMPLE);
//
//            if (passwordProvider != null) {
//                serviceImpl = new SecretCallbackHandlerServiceImpl();
//                serviceImpl.setSecretCallbackHandler(passwordProvider);  todo
//
//            }
//        }
//
//        if (serviceImpl == null) {
//            serviceImpl = new SecretCallbackHandlerServiceImpl();
//            serviceImpl.setSecretCallbackHandler(
//                    new SecretManagerSecretCallbackHandler(secretManager));
        }

        return serviceImpl;
    }


    private Properties loadProperties() {
        Properties properties = new Properties();
        String carbonHome = System.getProperty(CARBON_HOME);
        String filePath = carbonHome + File.separator +
                CONF_DIR + File.separator + SECURITY_DIR+ File.separator + SECRET_CONF;

        File dataSourceFile = new File(filePath);
        if (!dataSourceFile.exists()) {
            return properties;
        }

        InputStream in = null;
        try {
            in = new FileInputStream(dataSourceFile);
            properties.load(in);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at :" + filePath;
            log.warn(msg, e);
            return properties;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {

                }
            }
        }
        return properties;
    }
}
