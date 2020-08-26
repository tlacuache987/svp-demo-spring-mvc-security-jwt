package org.certificatic.spring.mvc.jwtsecurity.practica35._configuration;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

public class JwtAuthroizationFilter extends GenericFilterBean {

	private static final Logger log = LoggerFactory.getLogger(JwtAuthroizationFilter.class);
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest)req;
		
		Authentication authentication = getAuthentication(request);
		
		if (authentication == null) {
			chain.doFilter(req, res);
			return;
		}
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}
	
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String jwt = request.getHeader("Authorization");
		
		if(jwt == null)
			return null;
		
		if (!jwt.isEmpty() && jwt.startsWith("Bearer")) {
			
			Jws<Claims> parsedToken = null;

			Claims claims = null;
			
			List<GrantedAuthority> authorities = null;
			
			try {
				
				parsedToken = JwtUtils.parseJwt(jwt);

				claims = parsedToken.getBody();
				
				authorities = ((List<?>) claims.get("rol"))
												.stream()
												.map(authority -> new SimpleGrantedAuthority((String) authority))
												.collect(Collectors.toList());
			} catch (ExpiredJwtException exception) {
				log.warn("Request to parse expired JWT : {} failed : {}", jwt, exception.getMessage());
				
			} catch (UnsupportedJwtException exception) {
				log.warn("Request to parse unsupported JWT : {} failed : {}", jwt, exception.getMessage());
				
			} catch (MalformedJwtException exception) {
				log.warn("Request to parse invalid JWT : {} failed : {}", jwt, exception.getMessage());
				
			} catch (SignatureException exception) {
				log.warn("Request to parse JWT with invalid signature : {} failed : {}", jwt, exception.getMessage());
				
			} catch (IllegalArgumentException exception) {
				log.warn("Request to parse empty or null JWT : {} failed : {}", jwt, exception.getMessage());
			}
			
			if(claims != null)
				if (!claims.getSubject().isEmpty()) {
					return new UsernamePasswordAuthenticationToken(
												createUserWithoutCredentials(claims.getSubject(), authorities), null, authorities);
				}
		} 

		return null;
	}

	private static UserDetails createUserWithoutCredentials(String username, List<GrantedAuthority> authorities) {
		User user = new User(username, "*****", authorities);
		user.eraseCredentials();
		return user;
	}
}
