package com.course.apisecurity.api.server.auditlog;

import java.time.LocalTime;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.course.apisecurity.api.request.util.OriginalStringRequest;

@RestController
@RequestMapping("/api/log/v1")
public class RandomStatusApi {

	@GetMapping(value = "/random-status", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
	public ResponseEntity<String> randomStatus(@RequestBody(required = false) OriginalStringRequest request) {
		var randomStatus = switch (ThreadLocalRandom.current().nextInt() % 3) {
		case 0:
			yield HttpStatus.CREATED;
		case 1:
			yield HttpStatus.NO_CONTENT;
		case 2:
			yield HttpStatus.PAYMENT_REQUIRED;
		default:
			yield HttpStatus.INTERNAL_SERVER_ERROR;
		};

		return ResponseEntity.status(randomStatus).body(LocalTime.now().toString());
	}

}
