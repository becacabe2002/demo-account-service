package com.wiinvent.account.accountservice.domain.utils;

import com.wiinvent.account.accountservice.domain.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@Log4j2
public class JwtUtils {

    @Value("${application.security.jwt.secret-key}")
    private String jwtSecret;

    @Value("${application.security.jwt.expiration}")
    private long jwtExprirationMs;
    // todo create generateRefreshToken()

    //region master branch method
//    public String getUserNameFromJwtToken(String token){
//        log.debug("exp config" + jwtExprirationMs);
//
//        log.debug(Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getExpiration());
//        log.debug(Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getIssuedAt());
//        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
//    }
    //endregion


    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.
                parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ jwtExprirationMs))
                .signWith(getSignInKey())
                .compact();
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean checkTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !checkTokenExpired(token));
    }

    private boolean checkTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    //region master branch method
//    public String generateJwtToken(Authentication authentication){
//        /**
//         * func getPrincipal() return Principal obj associated with authentication obj
//         * Principle obj represents the identity of the user (username, password)
//         */
//        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
//
//        log.info(
//                "exp gen: " + Date.from(ZonedDateTime.now().plusSeconds(jwtExprirationMs/1000).toInstant())
//        );
//
//        log.debug("gen at " + System.currentTimeMillis());
//        return Jwts.builder()
//                .setSubject((userPrincipal.getUsername()))
//                .setIssuedAt(new Date())
//                .setExpiration(
//                        Date.from(ZonedDateTime.now().plusSeconds(jwtExprirationMs/1000).toInstant())
//                )
//                .signWith(SignatureAlgorithm.HS512, jwtSecret)
//                .compact()
//                ;
//    }
    //endregion

    //region master branch method
//    public boolean validateJwtToken(String authToken){
//        try{
//            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
//            return true;
//        } catch (SignatureException e){
//            log.error("Invalid JWT signature: {}", e.getMessage());
//        }catch (MalformedJwtException e) {
//            log.error("Invalid JWT token: {}", e.getMessage());
//        } catch (ExpiredJwtException e) {
//            log.error("JWT token is expired: {}", e.getMessage());
//        } catch (UnsupportedJwtException e) {
//            log.error("JWT token is unsupported: {}", e.getMessage());
//        } catch (IllegalArgumentException e) {
//            log.error("JWT claims string is empty: {}", e.getMessage());
//        }
//        return false;
//    }
    //end region
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
