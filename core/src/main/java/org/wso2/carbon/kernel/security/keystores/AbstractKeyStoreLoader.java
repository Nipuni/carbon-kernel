package org.wso2.carbon.kernel.security.keystores;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.kernel.security.IKeyStoreLoader;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * Provides the base for loading KeyStores
 */
public abstract class AbstractKeyStoreLoader implements IKeyStoreLoader {

    protected Log log;

    protected AbstractKeyStoreLoader() {
        log = LogFactory.getLog(this.getClass());
    }

    /**
     * Constructs a KeyStore based on keystore location , keystore password , keystore type and
     * provider
     *
     * @param location      The location of the KeyStore
     * @param storePassword Password to unlock KeyStore
     * @param storeType     KeyStore type
     * @param provider      Provider
     * @return KeyStore Instance
     */
    protected KeyStore getKeyStore(String location, String storePassword,
                                   String storeType,
                                   String provider) {

        File keyStoreFile = new File(location);
        if (!keyStoreFile.exists()) {
            handleException("KeyStore can not be found at ' " + keyStoreFile + " '");
        }

        BufferedInputStream bis = null;
        try {
            if (log.isDebugEnabled()) {
                log.debug("Loading KeyStore from : " + location + " Store-Type : " +
                        storeType + " Provider : " + provider);
            }
            bis = new BufferedInputStream(new FileInputStream(keyStoreFile));
            KeyStore keyStore;
            if (provider != null) {
                keyStore = KeyStore.getInstance(storeType, provider);
            } else {
                keyStore = KeyStore.getInstance(storeType);
            }
            keyStore.load(bis, storePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (IOException e) {
            handleException("IOError loading keyStore from ' " + location + " ' ", e);
        } catch (NoSuchAlgorithmException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (CertificateException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (NoSuchProviderException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } finally {
            if (bis != null) {
                try {
                    bis.close();
                } catch (IOException ignored) {
                }
            }
        }
        return null;
    }

    protected void handleException(String msg, Exception e) {
        log.error(msg, e);
        throw new RuntimeException(msg, e);
    }

    protected void handleException(String msg) {
        log.error(msg);
        throw new RuntimeException(msg);
    }
}

