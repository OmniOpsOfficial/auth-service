package me.omniops.users;

import io.quarkus.runtime.annotations.StaticInitSafe;
import io.smallrye.config.ConfigMapping;

@StaticInitSafe
@ConfigMapping(prefix = "portal")
public interface PortalConfig {

    Config config();

    interface Config {
        Sso sso();
    }

    interface Sso {
        String domain();

        String realm();

        String clientId();

        String clientSecret();
    }

}
