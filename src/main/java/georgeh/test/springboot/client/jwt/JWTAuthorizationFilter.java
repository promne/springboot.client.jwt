package georgeh.test.springboot.client.jwt;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private final String BEARER_TYPE = "Bearer";

    private final JwkProvider jwkProvider;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, URL jwkUrl)  {
        super(authenticationManager);

        jwkProvider = new JwkProviderBuilder(jwkUrl)
                .cached(10, 24, TimeUnit.HOURS)
                .rateLimited(10, 1, TimeUnit.MINUTES)
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        var token = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
                .filter(it -> it.toLowerCase().startsWith(BEARER_TYPE.toLowerCase()))
                .map(it -> it.substring(BEARER_TYPE.length()).trim());

        if (token.isEmpty()) {
            throw new AuthorizationServiceException("Authorization header is missing");
        }

        var jwt = validateToken(token.get());

        // extract values and insert them into security context
        var scopesAuthorities = jwt.getClaim("scopes").asList(String.class).stream().map(scope -> "SCOPE_"+scope).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(jwt.getSubject(), null, scopesAuthorities));

        chain.doFilter(request, response);
    }

    private DecodedJWT validateToken(String token) {
        try {
            var jwt = JWT.decode(token);
            var jwk = jwkProvider.get(jwt.getKeyId());
            var algorithm = Algorithm.RSA512((RSAPublicKey) jwk.getPublicKey(), null);
            JWT.require(algorithm).build().verify(jwt);
            return jwt;
        } catch (JwkException | JWTDecodeException e) {
            throw new AuthorizationServiceException(e.getMessage());
        }
   }

}
