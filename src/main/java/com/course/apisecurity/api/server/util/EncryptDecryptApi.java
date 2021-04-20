package com.course.apisecurity.api.server.util;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.course.apisecurity.api.request.util.OriginalStringRequest;
import com.course.apisecurity.util.EncryptDecryptUtil;

@RestController
@RequestMapping("/api")
public class EncryptDecryptApi {

	private static final String SECRET_KEY = "MySecretKey12345";

	@GetMapping(value = "/encrypt/aes", produces = MediaType.TEXT_PLAIN_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public String encryptAes(@RequestBody(required = true) OriginalStringRequest original) throws Exception {
		return EncryptDecryptUtil.encryptAes(original.getText(), SECRET_KEY);
	}

	@GetMapping(value = "/decrypt/aes", produces = MediaType.TEXT_PLAIN_VALUE)
	public String decryptAes(@RequestParam(required = true, name = "encrypted") String encrypted) throws Exception {
		return EncryptDecryptUtil.decryptAes(encrypted, SECRET_KEY);
	}

}
