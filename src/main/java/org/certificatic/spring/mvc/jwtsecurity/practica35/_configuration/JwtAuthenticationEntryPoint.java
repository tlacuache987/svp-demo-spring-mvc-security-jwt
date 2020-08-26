package org.certificatic.spring.mvc.jwtsecurity.practica35._configuration;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import lombok.Getter;
import lombok.Setter;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private @Getter @Setter String realmName;

	public JwtAuthenticationEntryPoint(String realmName) {
		super();
		this.realmName = realmName;
	}

	@Override
	public void commence(final HttpServletRequest request, final HttpServletResponse response,
			final AuthenticationException authException) throws IOException, ServletException {

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.addHeader("WWW-Authenticate", "Bearer realm=\"" + this.getRealmName() + "\"");

		PrintWriter writer = response.getWriter();
		writer.println("HTTP Status 401 : " + authException.getMessage());

	}
	
}
