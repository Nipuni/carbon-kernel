package org.wso2.carbon.kernel.security.definition;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.security.CipherOperationMode;
import org.wso2.carbon.kernel.security.EncodingType;

/**
 * Encapsulates the cipher related information
 */
public class CipherInformation {

    /**
     * Default cipher algorithm
     */
    public static final String DEFAULT_ALGORITHM = "RSA";

    private static final Logger log = LoggerFactory.getLogger(CipherInformation.class);

    /* Cipher algorithm */
    private String algorithm = DEFAULT_ALGORITHM;

    /* Cipher operation mode - ENCRYPT or DECRYPT */
    private CipherOperationMode cipherOperationMode;

    /* Mode of operation - ECB,CCB,etc*/
    private String mode;

    /* Type of the input to the cipher */
    private EncodingType inType;

    /* Type of the output from the cipher*/
    private EncodingType outType;

    /* Ciphering type - asymmetric , symmetric*/
    private String type;

    private String provider;

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        if (algorithm == null || "".equals(algorithm)) {
            log.info("Given algorithm is null, using a default one : RSA");
        }
        this.algorithm = algorithm;
    }

    public CipherOperationMode getCipherOperationMode() {
        return cipherOperationMode;
    }

    public void setCipherOperationMode(CipherOperationMode operationMode) {
        this.cipherOperationMode = operationMode;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public EncodingType getInType() {
        return inType;
    }

    public void setInType(EncodingType inType) {
        this.inType = inType;
    }

    public EncodingType getOutType() {
        return outType;
    }

    public void setOutType(EncodingType outType) {
        this.outType = outType;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
}

