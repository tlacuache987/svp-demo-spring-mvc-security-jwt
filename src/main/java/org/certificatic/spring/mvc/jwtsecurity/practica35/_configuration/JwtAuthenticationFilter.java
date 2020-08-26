package org.certificatic.spring.mvc.jwtsecurity.practica35._configuration;

import java.io.PrintWriter;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.SneakyThrows;

/**
 * Class for authentication sending username and password credentials with
 * x-www-form-urlencoded parameters
 * @author xvhx
 *
 */
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	protected static final String USERNAME_PARAMETER = "username";
	protected static final String PASSWORD_PARAMETER = "password";

	protected boolean postOnly = true;

	public JwtAuthenticationFilter(String loginUrl, AuthenticationManager authenticationManager) {
		super(new AntPathRequestMatcher(loginUrl));
		
		this.setAuthenticationManager(authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}

		String username = request.getParameter(USERNAME_PARAMETER);
		String password = request.getParameter(PASSWORD_PARAMETER);

		if (username == null) {
			throw new AuthenticationServiceException("username must be provided");
		}

		if (password == null) {
			throw new AuthenticationServiceException("password must be provided");
		}

		username = username.trim();

		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,
				password);

		return this.getAuthenticationManager().authenticate(authenticationToken);
	}

	@SneakyThrows
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain, Authentication authentication) {

		User user = ((User) authentication.getPrincipal());

		List<String> roles = user.getAuthorities().stream()
												  .map(GrantedAuthority::getAuthority)
												  .collect(Collectors.toList());

		String jwt = JwtUtils.buildJwt(user.getUsername(), roles);

		response.addHeader("Authorization", "Bearer " + jwt);
		response.addHeader("Content-Type", "application/json");

		PrintWriter writer = response.getWriter();
		writer.write(JwtUtils.jwtResponse(jwt));
		writer.flush();
	}
	
}
