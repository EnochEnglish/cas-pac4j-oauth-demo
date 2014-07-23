package org.jasig.cas.support.oauth;

import java.util.ArrayList;
import java.util.List;

import javax.validation.constraints.NotNull;

import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.support.oauth.services.OAuthRegisteredService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * Load the client definition based on the CAS services registry.
 *
 * @author Jerome Leleu
 * @author Joe McCall
 * @since 4.1
 */
public class CasClientDetailsService implements ClientDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasClientDetailsService.class);

    private final List<String> AUTHORIZATION_CODE_GRANT_TYPE;

    @NotNull
    private final ServicesManager servicesManager;

    public CasClientDetailsService(final ServicesManager servicesManager) {
        super();
        this.servicesManager = servicesManager;
        AUTHORIZATION_CODE_GRANT_TYPE = new ArrayList<String>();
        AUTHORIZATION_CODE_GRANT_TYPE.add("authorization_code");
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {

        // iterate over all registered services to find the right one
        for (final RegisteredService service : servicesManager.getAllServices()) {

            // use a real OAuth CAS service definition
            if (service instanceof OAuthRegisteredService) {
                final OAuthRegisteredService oauthService = (OAuthRegisteredService) service;
                if (clientId.equals(oauthService.getId())) {
                    final BaseClientDetails details = new BaseClientDetails();
                    details.setClientId(clientId);
                    details.setClientSecret(oauthService.getClientSecret());
                    details.setAuthorizedGrantTypes(AUTHORIZATION_CODE_GRANT_TYPE);

                    LOGGER.debug("Found the client definition: {} for the clientId: {}", details, clientId);
                    return details;
                }

            // based on regular CAS service definition
            } else {
                if (clientId.equals(service.getName())) {
                    final BaseClientDetails details = new BaseClientDetails();
                    details.setClientId(clientId);
                    details.setClientSecret(service.getDescription());
                    details.setAuthorizedGrantTypes(AUTHORIZATION_CODE_GRANT_TYPE);

                    LOGGER.debug("Found the client definition: {} for the clientId: {}", details, clientId);
                    return details;
                }
            }
        }

        throw new ClientRegistrationException("Client not found with clientId: " + clientId);
    }
}
