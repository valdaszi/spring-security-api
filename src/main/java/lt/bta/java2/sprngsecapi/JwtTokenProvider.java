package lt.bta.java2.sprngsecapi;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    @Value("${security.jwt.token.secret-key}") // base64 encoded 256bits (32bytes)
    private String secretKey;

    private Algorithm algorithm;

    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds = 60 * 60 * 1000; // 1h

    @Resource
    private UserDetailsService userDetailsService;

    private static final String AUTHENTICATION_SCHEME = "Bearer";
    private static final String CLAIM_USER = "user";
    private static final String CLAIM_ROLE = "role";

    @PostConstruct
    protected void init() {
        byte[] key = Base64.getDecoder().decode(secretKey);
        algorithm = Algorithm.HMAC256(key);
    }

    public String createToken(String username, List<String> roles) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return JWT.create()
                .withIssuer("my app")
                .withJWTId(UUID.randomUUID().toString())
                .withClaim(CLAIM_USER, username)
                .withArrayClaim(CLAIM_ROLE, roles.toArray(new String[0]))
                .withIssuedAt(now)
                .withExpiresAt(validity)
                .sign(algorithm);
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getClaim(CLAIM_USER).asString();
    }

    public String resolveToken(HttpServletRequest req) {
        String authorizationHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        return authorizationHeader != null && authorizationHeader.startsWith(AUTHENTICATION_SCHEME + " ") ?
                authorizationHeader.substring(AUTHENTICATION_SCHEME.length()).trim() : null;
    }

    public boolean validateToken(String token) {
        JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(token);
        return true;
    }

}
