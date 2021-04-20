package com.course.apisecurity.api.server.cors;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/cors/v1")
public class MadMaxApi {

	@GetMapping(value = "/mad", produces = MediaType.TEXT_PLAIN_VALUE)
//	@CrossOrigin(origins = "http://127.0.0.1:8080")
	public String mad() {
		return "Mad";
	}

	@PostMapping(value = "/max", produces = MediaType.TEXT_PLAIN_VALUE)
//	@CrossOrigin(origins = { "http://127.0.0.1:8080", "http://192.168.0.13:8080" })
	public String max() {
		return "Max";
	}

}
