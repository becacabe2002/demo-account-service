package com.wiinvent.account.accountservice.domain.security.jwt;

import com.wiinvent.account.accountservice.domain.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Log4j2
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private final JwtUtils jwtUtils;

    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,     // intercept every request
            @NonNull HttpServletResponse response,   // and then return data in response
            @NonNull FilterChain filterChain         // contains other filters
    ) throws ServletException, IOException {
        try{
            final String jwt = parseJwt(request);
            final String userEmail = jwtUtils.extractUsername(jwt);

            // if user has not been authenticated yet
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){

                // load UserDetails form DB
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // check if information in jwt is match with the fetched userDetails
                if (jwtUtils.checkTokenValid(jwt, userDetails)){
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // add authentication to context inside contextholder
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            // pass control to the next filter in the filter chain
            filterChain.doFilter(request, response);
        } catch (Exception e){
            log.error("Cannot set user authentication: {}", e);
        }

    }

    /**
     * Return Jwt String from request
     * @param request
     */
    private String parseJwt(HttpServletRequest request){
        String authHeader = request.getHeader("Authorization");

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;

    }
}
