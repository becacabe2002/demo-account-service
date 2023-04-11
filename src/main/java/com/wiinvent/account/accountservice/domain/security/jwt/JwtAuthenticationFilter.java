package com.wiinvent.account.accountservice.domain.security.jwt;

import com.wiinvent.account.accountservice.domain.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Log4j2
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,     // intercept every request
            @NonNull HttpServletResponse response,   // and then return data in response
            @NonNull FilterChain filterChain         // contains other filters
    ) throws ServletException, IOException {
        try{
            final String jwt = parseJwt(request);
            final String userEmail = jwtUtils.getUserNameFromJwtToken(jwt);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication().){

            }
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
