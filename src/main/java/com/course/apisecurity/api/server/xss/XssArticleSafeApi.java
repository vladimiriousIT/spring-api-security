package com.course.apisecurity.api.server.xss;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.course.apisecurity.api.response.xss.XssArticleSearchResponse;
import com.course.apisecurity.entity.XssArticle;
import com.course.apisecurity.repository.XssArticleRepository;

@RestController
@RequestMapping("/api/xss/safe/v1/article")
@CrossOrigin(origins = "http://localhost:3000")
public class XssArticleSafeApi {

	@Autowired
	private XssArticleRepository repository;

	@PostMapping(value = "", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.TEXT_MARKDOWN_VALUE)
	public String create(@RequestBody(required = true) XssArticle article) {
		var savedArticleId = repository.save(article);

		return "Saved as " + savedArticleId;
	}

	@GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
	public XssArticleSearchResponse search(@RequestParam(required = true) String query) {
		var articles = repository.findByArticleContainsIgnoreCase(query);

		var response = new XssArticleSearchResponse();
		response.setResult(articles);

		if (articles.size() < 100) {
			response.setQueryCount(
					"Search for " + query + " returns <strong>" + articles.size() + "</strong> results.");
		} else {
			response.setQueryCount(
					"Search for " + query + " returns too many results. <em>Use more specific keywords</em>");
		}

		return response;
	}

}
