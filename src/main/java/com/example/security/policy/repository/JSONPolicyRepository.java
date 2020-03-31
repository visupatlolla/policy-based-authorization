package com.example.security.policy.repository;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.expression.Expression;
import org.springframework.stereotype.Component;

import com.example.security.policy.AccessPolicy;
import com.example.security.policy.SpringExpressionDeserializer;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

@Component
public class JSONPolicyRepository implements PolicyRepository{

	private List<AccessPolicy> accessPolicies;
	private static String DEFAULT_POLICY_FILE_NAME = "access-policy.json";
	private String policyFileName = DEFAULT_POLICY_FILE_NAME;

    static final Logger logger = LoggerFactory.getLogger(JSONPolicyRepository.class);
	
	@Override
	public List<AccessPolicy> getAllAcessPoliciesByServiceId(String serviceId) {
		return accessPolicies;
	}
	
	public JSONPolicyRepository() {
		logger.debug("Loading policies in the JSONPolicyRepository constructor");
		loadAccessPolicies(this.policyFileName);
	}

	public JSONPolicyRepository(String policyFileName) {
		logger.debug("Loading policies from file {} in the JSONPolicyRepository constructor", policyFileName);
		loadAccessPolicies(policyFileName);
	}


	private void loadAccessPolicies(String policyFileName) {
		logger.debug("Loading {} from classpath", policyFileName);
		
		ObjectMapper mapper = new ObjectMapper();
		SimpleModule module = new SimpleModule();
		module.addDeserializer(Expression.class, new SpringExpressionDeserializer());
		mapper.registerModule(module);
		
		try (InputStream resource = new ClassPathResource(policyFileName).getInputStream()){
			accessPolicies = mapper.readValue(resource,new TypeReference<List<AccessPolicy>>(){});
		} catch (JsonMappingException e) {  // TODO consider throwing exception
			logger.error("Exception marshalling the JSON file - {}", policyFileName);
		} catch (IOException e) {
			logger.error("Exception reading the JSON file - {}", policyFileName);
		}
	}
	
	
}
