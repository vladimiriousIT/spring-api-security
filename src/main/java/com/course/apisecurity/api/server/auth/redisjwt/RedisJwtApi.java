package com.course.apisecurity.api.server.auth.redisjwt;

import java.time.LocalTime;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.course.apisecurity.constant.JwtConstant;
import com.course.apisecurity.entity.JwtData;
import com.course.apisecurity.service.RedisJwtService;

@RestController
@RequestMapping("/api/auth/redis-jwt/v1")
public class RedisJwtApi {

	@Autowired
	private RedisJwtService jwtService;

	@GetMapping(value = "/time", produces = MediaType.TEXT_PLAIN_VALUE)
	public String time(HttpServletRequest request) {
		var encryptedUsername = request.getAttribute(JwtConstant.REQUEST_ATTRIBUTE_USERNAME);

		return "Now is " + LocalTime.now() + ", accessed by " + encryptedUsername;
	}

	@PostMapping(value = "/login", produces = MediaType.TEXT_PLAIN_VALUE)
	public String login(HttpServletRequest request) {
		var encryptedUsername = (String) request.getAttribute(JwtConstant.REQUEST_ATTRIBUTE_USERNAME);

		var jwtData = new JwtData();
		jwtData.setUsername(encryptedUsername);

		var jwtToken = jwtService.store(jwtData);

		return jwtToken;
	}

	@DeleteMapping(value = "/logout", produces = MediaType.TEXT_PLAIN_VALUE)
	public String logout(@RequestHeader(required = true, name = HttpHeaders.AUTHORIZATION) String authorizationHeader) {
		var token = StringUtils.substring(authorizationHeader, "Bearer".length() + 1);

		jwtService.delete(token);
		return "Logged out";
	}

}
