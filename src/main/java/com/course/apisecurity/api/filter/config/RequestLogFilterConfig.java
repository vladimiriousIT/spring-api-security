package com.course.apisecurity.api.filter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

//@Configuration
public class RequestLogFilterConfig {

	@Bean
	public CommonsRequestLoggingFilter logFilter() {
		var filter = new CommonsRequestLoggingFilter();

		filter.setIncludeQueryString(true);
		filter.setIncludePayload(true);
		filter.setIncludeHeaders(true);

		return filter;
	}

}
