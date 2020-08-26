package org.certificatic.spring.mvc.jwtsecurity.practica35._configuration;

import org.certificatic.spring.mvc.jwtsecurity.practica35.controller.PathController;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableWebMvc
@ComponentScan(basePackageClasses = PathController.class)
public class ServletContextConfiguration {

}