package org.certificatic.spring.mvc.jwtsecurity.practica35.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController // Analiza Path Controller
public class PathController {

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String permitAll() {

		log.info("show info for all ------------------");

		return "This is info for all (no authentication required)";
	}

	@RequestMapping(value = "/welcome", method = RequestMethod.GET)
	public String welcome() {

		log.info("show welcome info ------------------");

		UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

		return "Welcome " + principal.getUsername();
	}

}
