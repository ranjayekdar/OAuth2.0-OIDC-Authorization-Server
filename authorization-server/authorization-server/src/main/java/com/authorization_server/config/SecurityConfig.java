package com.authorization_server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
	@Order(1)
	public SecurityFilterChain webSecurityFilterChain(HttpSecurity httpSecurity, RegisteredClientRepository registeredClientRepository) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
		.tokenGenerator(tokenGenerator())
		.clientAuthentication(authentication->{
			authentication.authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter());
			authentication.authenticationProvider(new PublicClientRefreshProvider(registeredClientRepository));
		})
		.oidc(Customizer.withDefaults());

		httpSecurity.exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
		httpSecurity.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
		return httpSecurity.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain appSecurity(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults());
		return httpSecurity.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://localhost:8080").build();
	}
	
	private OAuth2TokenCustomizer<JwtEncodingContext> customizer() {
		return context->{
			if(context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
				Authentication authentication = context.getPrincipal();
				Set<String> authorities = new HashSet<>();
				 Collection<? extends GrantedAuthority> authorities2 = authentication.getAuthorities();
				for (GrantedAuthority grantedAuthority : authorities2) {
					authorities.add(grantedAuthority.getAuthority());
				}
				context.getClaims().claim("authorities", authorities);
			}
		};
	}
	
	@Bean
	OAuth2TokenGenerator<OAuth2Token> tokenGenerator() throws Exception {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
		jwtGenerator.setJwtCustomizer(customizer());
		OAuth2TokenGenerator<OAuth2RefreshToken> auth2RefreshTokenGenerator = new CustomOAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(jwtGenerator,auth2RefreshTokenGenerator);
	}
	
	public final class CustomOAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
		
		public CustomOAuth2RefreshTokenGenerator(){}

		private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(
				Base64.getUrlEncoder().withoutPadding(), 96);

		@Nullable
		@Override
		public OAuth2RefreshToken generate(OAuth2TokenContext context) {
			if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
			return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
		}

	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey public1 = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey private1 = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(public1).privateKey(private1).keyID(UUID.randomUUID().toString()).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<SecurityContext>(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	private static final class PublicClientRefreshTokenAuthentication extends OAuth2ClientAuthenticationToken {

		public PublicClientRefreshTokenAuthentication(String clientId) {
			super(clientId, ClientAuthenticationMethod.NONE, null, null);
		}

		public PublicClientRefreshTokenAuthentication(RegisteredClient registeredClient) {
			super(registeredClient, ClientAuthenticationMethod.NONE, null);
		}

		
	}

	private static final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter{

		@Override
		public Authentication convert(HttpServletRequest request) {
			String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
			if(!grantType.equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
				return null;
			}
			String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
			if(!StringUtils.hasText(clientId)) {
				return null;
			}
			return new PublicClientRefreshTokenAuthentication(clientId);
		}
		
	}
	
	private static final class PublicClientRefreshProvider implements AuthenticationProvider{
		
		private RegisteredClientRepository registeredClientRepository;

		public PublicClientRefreshProvider(RegisteredClientRepository registeredClientRepository) {
			this.registeredClientRepository=registeredClientRepository;
		}
		
		
		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			
			
			PublicClientRefreshTokenAuthentication publicClientRefreshTokenAuthentication = (PublicClientRefreshTokenAuthentication)authentication;
			if(!ClientAuthenticationMethod.NONE.equals(publicClientRefreshTokenAuthentication.getClientAuthenticationMethod())) {
				return null;
			}
			String clientId = publicClientRefreshTokenAuthentication.getPrincipal().toString();
			RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
			if(registeredClient==null) {
				throw new OAuth2AuthenticationException(new OAuth2Error("Invalid Client"));
			}
			
			if(!registeredClient.getClientAuthenticationMethods().contains(publicClientRefreshTokenAuthentication.getClientAuthenticationMethod())) {
				throw new OAuth2AuthenticationException(new OAuth2Error("Invalid method"));
			}
			
			return new PublicClientRefreshTokenAuthentication(registeredClient);
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return PublicClientRefreshTokenAuthentication.class.isAssignableFrom(authentication);
		}
		
	}
}
