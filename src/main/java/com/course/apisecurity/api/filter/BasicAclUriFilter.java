package com.course.apisecurity.api.filter;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import com.course.apisecurity.api.server.auth.basic.BasicAuthApi;
import com.course.apisecurity.entity.BasicAuthUser;
import com.course.apisecurity.repository.BasicAclUriRepository;
import com.course.apisecurity.repository.BasicAuthUserRepository;
import com.course.apisecurity.util.EncodeDecodeUtil;
import com.course.apisecurity.util.EncryptDecryptUtil;

//@Configuration
//@Order(1)
public class BasicAclUriFilter extends OncePerRequestFilter {

	@Autowired
	private BasicAuthUserRepository userRepository;

	@Autowired
	private BasicAclUriRepository uriRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		var basicAuthString = request.getHeader(HttpHeaders.AUTHORIZATION);
		var encodedAuthorizationString = StringUtils.substring(basicAuthString, "Basic".length()).trim();
		var plainAuthorizationString = EncodeDecodeUtil.decodeBase64(encodedAuthorizationString);
		var plainAuthorization = plainAuthorizationString.split(":");

		String encryptedUsername = StringUtils.EMPTY;

		try {
			encryptedUsername = EncryptDecryptUtil.encryptAes(plainAuthorization[0], BasicAuthApi.SECRET_KEY);
			var existingUser = userRepository.findByUsername(encryptedUsername).get();

			if (isValidUri(request.getMethod(), request.getRequestURI(), existingUser)) {
				filterChain.doFilter(request, response);
			} else {
				response.setStatus(HttpStatus.FORBIDDEN.value());
				response.setContentType(MediaType.TEXT_PLAIN_VALUE);
				response.getWriter().print("Method or URI is not allowed");

				return;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private boolean isValidUri(String method, String requestURI, BasicAuthUser existingUser) {
		for (var uriRef : existingUser.getAllowedUris()) {
			var allowedUri = uriRepository.findById(uriRef.getUriId()).get();

			if (StringUtils.equalsIgnoreCase(allowedUri.getMethod(), method)
					&& Pattern.matches(allowedUri.getUri(), requestURI)) {
				return true;
			}
		}

		return false;
	}

}
