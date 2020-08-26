package org.certificatic.spring.mvc.jwtsecurity.practica35._configuration;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.SneakyThrows;

/**
 * Class for authentication sending username and password credentials with
 * x-www-form-urlencoded parameters
 * @author xvhx
 *
 */
public class JwtUtils {

	public static final String SECRET_KEY = "+KbPeShVmYq3t6v9y$B&E)H@McQfTjWnZr4u7x!z%C*F-JaNdRgUkXp2s5v8y/B?";
	
	private static final int ONE_MINUTE = 60_000;
	private static final int EXPIRATION_TIME_IN_MINUTES = 60;

	private JwtUtils() {
	}

	public static String buildJwt(String username, List<String> roles) {
		
		Date expirationDate = new Date(System.currentTimeMillis() + (ONE_MINUTE * EXPIRATION_TIME_IN_MINUTES));

		String token = Jwts.builder()
							.signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()), SignatureAlgorithm.HS256)
							.setHeaderParam("typ", "JWT")
							.setHeaderParam("sop", "XRXT")
							.setIssuer("6-spring-mvc-security-jwt-javaconfig-rest app")
							.setAudience("some secure-app")
							.setSubject(username)
							.setExpiration(expirationDate)
							.claim("rol", roles)
							.compact();

		return token;
	}

	public static Jws<Claims> parseJwt(String jwt) {
		return Jwts.parser()
				.setSigningKey(JwtUtils.SECRET_KEY.getBytes())
				.parseClaimsJws(jwt.replace("Bearer ", ""));
	}

	@SneakyThrows
	public static String jwtResponse(String jwt) {
		Map<String, String> map = new HashMap<>();
		map.put("jwt", jwt);
		return new ObjectMapper().writeValueAsString(map);
	}

}
