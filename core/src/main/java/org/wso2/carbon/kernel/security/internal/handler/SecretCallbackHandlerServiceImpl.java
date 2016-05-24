package org.wso2.carbon.kernel.security.internal.handler;

import org.wso2.carbon.kernel.security.SecretCallbackHandler;

/**
 * Implementation for <code>SecretCallbackHandlerService</code>
 */
public class SecretCallbackHandlerServiceImpl implements SecretCallbackHandlerService {

    private SecretCallbackHandler secretCallbackHandler;

    public SecretCallbackHandler getSecretCallbackHandler() {
        return secretCallbackHandler;
    }

    public void setSecretCallbackHandler(SecretCallbackHandler secretCallbackHandler) {
        this.secretCallbackHandler = secretCallbackHandler;
    }
}
