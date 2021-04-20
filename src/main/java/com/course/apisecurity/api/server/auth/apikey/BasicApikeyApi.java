package com.course.apisecurity.api.server.auth.apikey;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.course.apisecurity.constant.ApikeyConstant;

@RestController
@RequestMapping("/api/auth/apikey/v1")
public class BasicApikeyApi {

	@GetMapping(value = "/add", produces = MediaType.TEXT_PLAIN_VALUE)
	public String add(@RequestParam(required = true, name = "a") int a,
			@RequestParam(required = true, name = "b") int b, HttpServletRequest request) {
		return "Result is " + (a + b) + ", accessed by "
				+ request.getAttribute(ApikeyConstant.REQUEST_ATTRIBUTE_USERNAME);
	}

}
