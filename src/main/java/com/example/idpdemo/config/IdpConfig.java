package com.example.idpdemo.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderServerBeanConfiguration;

import javax.servlet.Filter;
import java.util.Collection;

@Configuration
public class IdpConfig extends SamlIdentityProviderServerBeanConfiguration {
    private final AppProperties config;

    public IdpConfig(@Qualifier("appProperties") AppProperties config) {
        this.config = config;
    }

    @Override
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        return config;
    }

    /*private static SamlServerConfiguration configuration = new SamlServerConfiguration()
            .setNetwork(
                    new NetworkConfiguration()
                            .setConnectTimeout(5000)
                            .setReadTimeout(10000)
            )
            .setIdentityProvider(
                    new LocalIdentityProviderConfiguration()
                            .setPrefix(prefix)
                            .setSignMetadata(true)
                            .setSignAssertions(true)
                            .setWantRequestsSigned(true)
                            .setDefaultSigningAlgorithm(RSA_SHA256)
                            .setDefaultDigest(SHA256)
                            .setNameIds(
                                    asList(
                                            PERSISTENT,
                                            EMAIL,
                                            UNSPECIFIED
                                    )
                            )
                            .setEncryptAssertions(false)
                            .setKeyEncryptionAlgorithm(RSA_1_5)
                            .setProviders(new LinkedList<>())
            );*/

}
