package com.wiinvent.account.accountservice.domain.utils;

import com.wiinvent.account.accountservice.domain.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

//import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;

@Component
@Log4j2
public class JwtUtils {
    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.token-expire-time}")
    private long jwtExprirationMs;
    // todo create generateJwtToken()

    // todo create generateRefreshToken()

    public String getUserNameFromJwtToken(String token){
        log.debug("exp config" + jwtExprirationMs);

        log.debug(Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getExpiration());
        log.debug(Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getIssuedAt());
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    // region "Another implementation of getUserNameFromJwtToken"
//    public String extractUsername(String token){
//        return extractClaim(token, Claims::getSubject);
//    }
//
//
//
//    private Key getSignInKey() {
//        byte[] keyBytes = .BASE64.decode(secretKey);
//        return Keys.hmacShaKeyFor(keyBytes);
//    }
//
//
//    private Claims extractAllClaims(String token) {
//        return Jwts
//                .parserBuilder()
//                .setSigningKey(getSignInKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
    //endregion

    public String generateJwtToken(Authentication authentication){
        /**
         * func getPrincipal() return Principal obj associated with authentication obj
         * Principle obj represents the identity of the user (username, password)
         */
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        log.info(
                "exp gen: " + Date.from(ZonedDateTime.now().plusSeconds(jwtExprirationMs/1000).toInstant())
        );

        log.debug("gen at " + System.currentTimeMillis());
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(
                        Date.from(ZonedDateTime.now().plusSeconds(jwtExprirationMs/1000).toInstant())
                )
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact()
                ;
    }

    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e){
            log.error("Invalid JWT signature: {}", e.getMessage());
        }catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
