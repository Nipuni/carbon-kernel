package org.wso2.carbon.kernel.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * Created by nipuni on 5/19/16.
 */
public class MiscellaneousUtil {

    private static Logger log = LoggerFactory.getLogger(MiscellaneousUtil.class);

    private MiscellaneousUtil() {
    }

    /**
     * Helper method to get the value of the property from a given property bag
     *
     * @param properties   The property collection
     * @param name         The name of the property
     * @param defaultValue The default value for the property
     * @return The value of the property if it is found , otherwise , default value
     */
    public static String getProperty(Properties properties, String name, String defaultValue) {

        String result = properties.getProperty(name);
        if ((result == null || result.length() == 0) && defaultValue != null) {
            if (log.isDebugEnabled()) {
                log.debug("The name with ' " + name + " ' cannot be found. " +
                        "Using default value " + defaultValue);
            }
            result = defaultValue;
        }
        if (result != null) {
            return result.trim();
        } else {
            return defaultValue;
        }
    }
}
