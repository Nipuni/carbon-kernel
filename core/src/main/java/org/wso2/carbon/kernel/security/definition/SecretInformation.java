package org.wso2.carbon.kernel.security.definition;


import org.wso2.carbon.kernel.security.SecretResolver;

/**
 * Encapsulates the All information related to a DataSource
 * TODO - properly remove SecretResolve instances
 */
public class SecretInformation {

    private String user;
    private String aliasSecret;
    private String secretPrompt;
    private SecretResolver localSecretResolver;
    private SecretResolver globalSecretResolver;
    private String token;

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getAliasSecret() {
        return aliasSecret;
    }

    public void setAliasSecret(String aliasSecret) {
        this.aliasSecret = aliasSecret;
    }

    public String getSecretPrompt() {
        return secretPrompt;
    }

    public void setSecretPrompt(String secretPrompt) {
        this.secretPrompt = secretPrompt;
    }

    /**
     * Get actual password based on SecretCallbackHandler and alias password
     * If SecretCallbackHandler is null, then returns alias password
     *
     * @return Actual password
     */
    public String getResolvedSecret() {

        SecretResolver secretResolver = null;

        if (localSecretResolver != null && localSecretResolver.isInitialized()) {
            secretResolver = localSecretResolver;
        } else if (globalSecretResolver != null && globalSecretResolver.isInitialized()
                && globalSecretResolver.isTokenProtected(token)) {
            secretResolver = globalSecretResolver;
        }

        if (secretResolver != null) {
            if (aliasSecret != null && !"".equals(aliasSecret)) {
                if (secretPrompt == null) {
                    return secretResolver.resolve(aliasSecret);
                } else {
                    return secretResolver.resolve(aliasSecret, secretPrompt);
                }
            }
        }
        return aliasSecret;
    }

    public SecretResolver getLocalSecretResolver() {
        return localSecretResolver;
    }

    public void setLocalSecretResolver(SecretResolver localSecretResolver) {
        this.localSecretResolver = localSecretResolver;
    }

    public SecretResolver getGlobalSecretResolver() {
        return globalSecretResolver;
    }

    public void setGlobalSecretResolver(SecretResolver globalSecretResolver) {
        this.globalSecretResolver = globalSecretResolver;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
