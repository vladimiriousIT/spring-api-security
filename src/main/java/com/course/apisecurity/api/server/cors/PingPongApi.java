package com.course.apisecurity.api.server.cors;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/cors/v1")
//@CrossOrigin(methods = RequestMethod.GET)
public class PingPongApi {

	@GetMapping(value = "/ping", produces = MediaType.TEXT_PLAIN_VALUE)
	public String ping() {
		return "Ping";
	}

	@PostMapping(value = "/pong", produces = MediaType.TEXT_PLAIN_VALUE)
	public String pong() {
		return "Pong";
	}

}
