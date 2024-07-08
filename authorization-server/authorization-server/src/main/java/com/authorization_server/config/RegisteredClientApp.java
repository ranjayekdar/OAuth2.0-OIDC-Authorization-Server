package com.authorization_server.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@Configuration
public class RegisteredClientApp {

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client")
				.clientSecret("secret").scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope(OidcScopes.EMAIL)
				.redirectUri("http://localhost:8081/login/oauth2/code/client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantTypes(grantType -> {
					grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
					grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
					grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
				}).clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		return new InMemoryRegisteredClientRepository(registeredClient);
	}

}
