package com.example.security.policy;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.server.PathContainer;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

public class AntPathMatcherLearningTest {

	private AntPathMatcher mather = new AntPathMatcher();
	
	@Test
	public void learningOverlappingPathMatching() {
		String pattern = "/resource/{businessAccount}/**";
		Assert.assertTrue(mather.match(pattern, "/resource/123/**"));
		Assert.assertTrue(mather.match("/**", pattern));
	}

	@Test
	public void anotherLearningOverlappingPathMatching() {
		PathPatternParser parser = new PathPatternParser();
		PathPattern pattern = parser.parse("/resource/{businessAccount}");
		Assert.assertFalse(pattern.matches(toPathContainer("/**")));
		Assert.assertFalse(pattern.matches(toPathContainer("/resource/123/abc")));
		Assert.assertFalse(pattern.matches(toPathContainer("/resource/123/abc/134")));
		Assert.assertFalse(pattern.matches(toPathContainer("/resourceA/123/abc")));
	}

	@Test
	public void learningPathMatching() {
		PathPatternParser parser = new PathPatternParser();
		PathPattern pattern = parser.parse("/**");
		Assert.assertTrue(pattern.matches(toPathContainer("/resource/123/**")));
		Assert.assertTrue(pattern.matches(toPathContainer("/resource")));
		Assert.assertTrue(pattern.matches(toPathContainer("/xyz/123")));
	}
	
	private PathContainer toPathContainer(String path) {
		return PathContainer.parsePath(path);
	}

}
