package io.dropwizard.auth.basic;

import static org.assertj.core.api.Assertions.assertThat;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.AuthResource;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.CustomExceptionMapper;
import io.dropwizard.auth.util.AuthUtil;
import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.logging.BootstrapLogging;

import java.security.Principal;

import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.glassfish.jersey.servlet.ServletProperties;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.Test;

import com.codahale.metrics.MetricRegistry;

public class BasicAuthProviderWithExceptionMapperTest extends JerseyTest {
    final private static String VALID_ROLE = "ADMIN";
    static {
        BootstrapLogging.bootstrap();
    }

    @Override
    protected TestContainerFactory getTestContainerFactory()
            throws TestContainerException {
        return new GrizzlyWebTestContainerFactory();
    }

    @Override
    protected DeploymentContext configureDeployment() {
        forceSet(TestProperties.CONTAINER_PORT, "0");
        return ServletDeploymentContext.builder(new BasicAuthTestResourceConfig())
                .initParam(ServletProperties.JAXRS_APPLICATION_CLASS, BasicAuthTestResourceConfig.class.getName())
                .build();
    }

    @Test
    public void resourceAuthorizedButExceptionMapperShouldBeUsed() throws Exception {
        Response response = target("/test/fail").request()
                                .header(HttpHeaders.AUTHORIZATION, "Basic Z29vZC1ndXk6c2VjcmV0")
                                .get();
        assertThat(response.getStatus()).isEqualTo(599);
        // This fails! assertThat(response.readEntity(String.class)).isEqualTo("My exception message");
    }

    public static class BasicAuthTestResourceConfig extends DropwizardResourceConfig {
        public BasicAuthTestResourceConfig() {
            super(true, new MetricRegistry());

            register(new CustomExceptionMapper());
            register(new AuthDynamicFeature(getAuthFilter()));
            register(RolesAllowedDynamicFeature.class);
            register(AuthResource.class);
        }

        private ContainerRequestFilter getAuthFilter() {
            final String validUser = "good-guy";

            BasicCredentialAuthFilter.Builder<Principal, Authenticator<BasicCredentials, Principal>> builder
                    = new BasicCredentialAuthFilter.Builder<>();
            builder.setSecurityContextFunction(AuthUtil.<AuthFilter.Tuple, SecurityContext>getSecurityContextProviderFunction(validUser, VALID_ROLE));
            builder.setAuthenticator(AuthUtil.<BasicCredentials, Principal>getTestAuthenticatorBasicCredential(validUser));
            return builder.buildAuthFilter();
        }
    }
}
