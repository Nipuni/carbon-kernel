package org.wso2.carbon.kernel.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

/**
 * Responsible for resolving secrets such as password. The secrets this SecretResolver should be
 * resolved , can be  given as protected Tokens and the use of this class can explicitly check
 * whether a token is protected.
 */
public class SecretResolver {

    private static Logger log = LoggerFactory.getLogger(SecretResolver.class);

    private boolean initialized = false;

    private final ArrayList<String> protectedTokens = new ArrayList<String>();

    private SecretLoadingModule secretLoadingModule;

    private final static String DEFAULT_PROMPT = "password > ";

    /**
     * Initializes by giving an instance of <code>SecretCallbackHandler </code> to be used to
     * retrieve secrets
     *
     * @param secretCallbackHandler <code>SecretCallbackHandler </code> instance
     */
    public void init(SecretCallbackHandler secretCallbackHandler) {

        if (initialized) {
            if (log.isDebugEnabled()) {
                log.debug("SecretResolver already has been started.");
            }
            return;
        }

        if (secretCallbackHandler == null) {
            throw new SecureVaultException("SecretResolver cannot be initialized. " +
                    "The provided SecretCallbackHandler is null", log);

        }

        this.secretLoadingModule = new SecretLoadingModule();
        this.secretLoadingModule.init(new SecretCallbackHandler[]{secretCallbackHandler});
        this.initialized = true;
    }

    /**
     * Resolved given password using an instance of a PasswordProvider
     *
     * @param encryptedPassword Encrypted password
     * @return resolved password
     */
    public String resolve(String encryptedPassword) {

        return resolve(encryptedPassword, DEFAULT_PROMPT);
    }

    /**
     * Resolved given password using an instance of a PasswordProvider
     *
     * @param encryptedPassword Encrypted password
     * @param prompt            to be used to interact with user
     * @return resolved password
     */
    public String resolve(String encryptedPassword, String prompt) {

        assertInitialized();

        if (encryptedPassword == null || "".equals(encryptedPassword)) {
            if (log.isDebugEnabled()) {
                log.debug("Given Encrypted Password is empty or null. Returning itself");
            }
            return encryptedPassword;
        }

        SingleSecretCallback secretCallback = new SingleSecretCallback(encryptedPassword);

        secretCallback.setPrompt(prompt);

        secretLoadingModule.load(new SecretCallback[]{secretCallback});

        String plainText = secretCallback.getSecret();

        return plainText;
    }

    /**
     * Registers a token as a Protected Token
     *
     * @param token <code>String</code> representation of a token
     */
    public void addProtectedToken(String token) {
        assertInitialized();
        if (token != null && !"".equals(token)) {
            protectedTokens.add(token.trim());
        }
    }

    /**
     * Checks whether a token is a Protected Token
     *
     * @param token <code>String</code> representation of a token
     * @return <code>true</code> if the token is a Protected Token
     */
    public boolean isTokenProtected(String token) {
        assertInitialized();
        return token != null && !"".equals(token) && protectedTokens.contains(token.trim());
    }

    /**
     * Checks the state of the rule engine.
     * It is recommended to check state of the this component prior to access any methods of this
     *
     * @return <code>true<code> if the rule engine has been initialized
     */
    public boolean isInitialized() {
        return initialized;
    }

    private void assertInitialized() {
        if (!initialized) {
            throw new SecureVaultException("SecretResolver has not been initialized, " +
                    "it requires to be initialized, with the required " +
                    "configurations before starting", log);
        }
    }

    /**
     * Shutdown the secret resolver
     */
    public void shutDown() {
        initialized = false;
        secretLoadingModule = null;
        protectedTokens.clear();
    }
}

