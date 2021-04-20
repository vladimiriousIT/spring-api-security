package com.course.apisecurity.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.course.apisecurity.entity.XssArticle;

@Repository
public interface XssArticleRepository extends CrudRepository<XssArticle, Integer> {

	public List<XssArticle> findByArticleContainsIgnoreCase(String article);

}
