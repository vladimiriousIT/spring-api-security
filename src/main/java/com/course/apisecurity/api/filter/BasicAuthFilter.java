package com.course.apisecurity.api.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import com.course.apisecurity.api.server.auth.basic.BasicAuthApi;
import com.course.apisecurity.repository.BasicAuthUserRepository;
import com.course.apisecurity.util.EncodeDecodeUtil;
import com.course.apisecurity.util.EncryptDecryptUtil;
import com.course.apisecurity.util.HashUtil;

public class BasicAuthFilter extends OncePerRequestFilter {

	private BasicAuthUserRepository basicAuthUserRepository;

	public BasicAuthFilter(BasicAuthUserRepository repository) {
		this.basicAuthUserRepository = repository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		var basicAuthString = request.getHeader(HttpHeaders.AUTHORIZATION);

		try {
			if (isValidBasicAuth(basicAuthString)) {
				filterChain.doFilter(request, response);
			} else {
				response.setStatus(HttpStatus.UNAUTHORIZED.value());
				response.setContentType(MediaType.TEXT_PLAIN_VALUE);
				response.getWriter().write("Invalid credential");

				return;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private boolean isValidBasicAuth(String basicAuthString) throws Exception {
		if (StringUtils.isBlank(basicAuthString)) {
			return false;
		}

		var encodedAuthorizationString = StringUtils.substring(basicAuthString, "Basic".length()).trim();
		var plainAuthorizationString = EncodeDecodeUtil.decodeBase64(encodedAuthorizationString);
		var plainAuthorization = plainAuthorizationString.split(":");
		var encryptedUsername = EncryptDecryptUtil.encryptAes(plainAuthorization[0], BasicAuthApi.SECRET_KEY);
		var submittedPassword = plainAuthorization[1];

		var existingData = basicAuthUserRepository.findByUsername(encryptedUsername);

		if (existingData.isEmpty()) {
			return false;
		}

		return HashUtil.isBcryptMatch(submittedPassword, existingData.get().getPasswordHash());
	}

}
