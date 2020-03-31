package com.example.security.policy.repository;

import java.util.List;

import com.example.security.policy.AccessPolicy;

public interface PolicyRepository {
	public List<AccessPolicy> getAllAcessPoliciesByServiceId(String serviceId);
}
