package com.example.security.policy.repository;


import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.example.security.policy.AccessPolicy;
import com.example.security.policy.repository.JSONPolicyRepository;

public class JSONPolicyRepositoryTest {

	JSONPolicyRepository repository = null;
	String serviceId = "im0813";

	@Before
	public  void loadPolicy() {
		repository = new JSONPolicyRepository();
	}
	
	@Test
	public void testLoadingOfPoliciesFromJSON() {
		Assert.assertEquals(repository.getAllAcessPoliciesByServiceId(serviceId).size(), 1);
	}
	
	@Test
	public void checkCompEnginePolicyExists() {
		List<AccessPolicy> allPolicyRules = repository.getAllAcessPoliciesByServiceId(serviceId);
		AccessPolicy policy = allPolicyRules.get(0);
		Assert.assertEquals("/comparable-service/**", policy.getResource().get(0));
		Assert.assertEquals("GET", policy.getAction().get(0));
	}
	

	@Test
	public void loadPolicyFileFromAGivenFileName() {
		String fileName = "simple-policy.json";
		JSONPolicyRepository fileRepo = createRepository(fileName);
		List<AccessPolicy> allPolicyRules = fileRepo.getAllAcessPoliciesByServiceId(serviceId);
		AccessPolicy policy = allPolicyRules.get(0);
		Assert.assertEquals("/comparable-service/**", policy.getResource().get(0));
		Assert.assertEquals("GET", policy.getAction().get(0));
	}

	private JSONPolicyRepository createRepository(String fileName) {
		JSONPolicyRepository fileRepo = new JSONPolicyRepository(fileName);
		return fileRepo;
	}


	@Test
	public void loadFileThatDoesNotExist() {
		String fileName = "does-not-exist.json";
		JSONPolicyRepository fileRepo = createRepository(fileName);
		List<AccessPolicy> allPolicyRules = fileRepo.getAllAcessPoliciesByServiceId(serviceId);
		Assert.assertNull(allPolicyRules);
	}
	
	@Test
	public void loadFileWithInvalidExpressions() {
		String fileName = "invalid-policy.json";
		JSONPolicyRepository fileRepo = createRepository(fileName);
		List<AccessPolicy> allPolicyRules = fileRepo.getAllAcessPoliciesByServiceId(serviceId);
		Assert.assertNull(allPolicyRules);
	}

}