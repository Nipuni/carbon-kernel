package org.wso2.carbon.kernel.security.internal.handler;

import org.wso2.carbon.kernel.security.SecretCallbackHandler;

/**
 * Expose <code>SecretCallbackHandler</code> as a service
 */
public interface SecretCallbackHandlerService {

    /**
     * Returns the global secret call handler
     *
     * @return An instance of <code>SecretCallbackHandler</code>
     */
    SecretCallbackHandler getSecretCallbackHandler();

    /**
     * Register the global secret call handler
     *
     * @param secretCallbackHandler an instance of <code>SecretCallbackHandler</code>
     */
    void setSecretCallbackHandler(SecretCallbackHandler secretCallbackHandler);
}
