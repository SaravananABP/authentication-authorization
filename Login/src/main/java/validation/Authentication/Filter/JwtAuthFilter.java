package validation.Authentication.Filter;


import validation.Authentication.Service.JwtService;
import validation.Authentication.Service.UserInfoDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserInfoDetailsService userInfoDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            try {
                username = jwtService.extractUsername(token);
            } catch (io.jsonwebtoken.security.SignatureException ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token Signature");
                return;
            } catch (io.jsonwebtoken.ExpiredJwtException ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token Expired");
                return;
            } catch (io.jsonwebtoken.MalformedJwtException ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Malformed Token");
                return;
            } catch (io.jsonwebtoken.UnsupportedJwtException ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unsupported Token");
                return;
            } catch (Exception ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
                return;
            }
        } else {
            // Continue if no token is provided (for non-protected routes)
            filterChain.doFilter(request, response);
            return;
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userInfoDetailsService.loadUserByUsername(username);

            if (jwtService.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Continue the filter chain for further request processing
        filterChain.doFilter(request, response);
    }


}
