package com.example.security.policy;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.example.security.policy.PolicyEvaluator;
import com.example.security.policy.repository.JSONPolicyRepository;
import com.example.security.policy.repository.PolicyRepository;

@Configuration
public class PolicyConfiguration {
	
	@Bean
	public PolicyRepository policyRepository() {
		String fileName="test-access-policy.json";
		JSONPolicyRepository fileRepo = new JSONPolicyRepository(fileName);
		return fileRepo;
	}
	
	@Bean
	public PolicyEvaluator policyEvaluator() {
		return new PolicyEvaluator();
	}
	
	
}
