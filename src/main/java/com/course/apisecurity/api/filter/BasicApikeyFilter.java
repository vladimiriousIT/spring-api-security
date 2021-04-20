package com.course.apisecurity.api.filter;

import java.io.IOException;
import java.time.LocalDateTime;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import com.course.apisecurity.constant.ApikeyConstant;
import com.course.apisecurity.repository.BasicApikeyRepository;
import com.course.apisecurity.repository.BasicAuthUserRepository;

//@Configuration
public class BasicApikeyFilter extends OncePerRequestFilter {

	@Autowired
	private BasicAuthUserRepository basicAuthUserRepository;

	@Autowired
	private BasicApikeyRepository basicApikeyRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		var apikey = request.getHeader("X-Apikey");

		if (isValidApikey(apikey, request)) {
			filterChain.doFilter(request, response);
		} else {
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType(MediaType.TEXT_PLAIN_VALUE);
			response.getWriter().write("Invalid credential");

			return;
		}
	}

	private boolean isValidApikey(String apikey, HttpServletRequest request) {
		var apikeyFromStorage = basicApikeyRepository.findByApikeyAndExpiredAtAfter(apikey, LocalDateTime.now());

		if (apikeyFromStorage.isPresent()) {
			var currentUser = basicAuthUserRepository.findById(apikeyFromStorage.get().getUserId());
			request.setAttribute(ApikeyConstant.REQUEST_ATTRIBUTE_USERNAME, currentUser.get().getUsername());

			return true;
		}

		return false;
	}

}
