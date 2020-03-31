package com.example.security.policy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.server.PathContainer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import com.example.security.policy.repository.PolicyRepository;

@Component
public class PolicyEvaluator {

    private static final Logger logger = LoggerFactory.getLogger(PolicyEvaluator.class);
    
    private String ALLOW = "allow";
    private String USER_ROLE_KEY = "userRoles";
    private String USER_ENTITLEMENTS_KEY = "entitlements";
    private String CLAIMS_KEY = "claims";
    private String ROLE_KEY = "role";
    
	@Autowired
	private PolicyRepository policyRepository;
	
	@Value("${freddiemac.security.serviceId}") 
	String serviceId;
	
	public boolean check(Authentication authentication, HttpServletRequest request) {
		logger.debug("Access policy evaluation started");
		Jwt jwt = (Jwt)authentication.getPrincipal();
		Map<String, Object> claims = jwt.getClaims();
		return check(claims, request);
	}
	
	public boolean check(Map<String, Object> claims, HttpServletRequest request) {
		logger.debug("Start of Access policy evaluation of resource for each policy defined in the policy service");
		
		boolean accessGranted = false;
		boolean priorEvaluationForOverlappingResources = true;

		logger.debug("Initial accessGranted: {} and priorEvaluationForOverlappingResources: {}", accessGranted, priorEvaluationForOverlappingResources);
		
		List<AccessPolicy> allPolicyRules = getAllPolicies();
		
		if (allPolicyRules != null && allPolicyRules.size() > 0) {
			for (AccessPolicy accessPolicy : allPolicyRules) {
				if (doesResourceMatchRequestUri(accessPolicy.getResource(), request.getRequestURI())) {
					if(doesActionMatchRequestedAction(accessPolicy.getAction(), request.getMethod())) {
						if (doesRoleMatch(accessPolicy.getRole(), claims)) {
							if (doesConditionMatch(claims, request, accessPolicy)){
								if (isPolicyAllowed(accessPolicy)) {
									accessGranted = true;
								}else {
									accessGranted = false;
								}
							}	
						}
						
						priorEvaluationForOverlappingResources = priorEvaluationForOverlappingResources && accessGranted;
						logger.debug("priorEvaluationForOverlappingResources: {}", priorEvaluationForOverlappingResources);
					}
				}
			}
		}
		
		accessGranted = accessGranted && priorEvaluationForOverlappingResources;
		
		logger.info("Final policy evaluation outcome: {}", accessGranted);
		
		return accessGranted;
	}

	private boolean doesResourceMatchRequestUri(List<String> resource, String requestUri) {
		logger.debug("Given resource pattern {} and requested uri {}", resource, requestUri);
		
		boolean didResourceMatch = false;
		
		for(String eachResource: resource) {
			PathPatternParser parser = new PathPatternParser();
			parser.setCaseSensitive(false);
			PathPattern pattern = parser.parse(eachResource);
			if (pattern.matches(toPathContainer(requestUri))) {
				didResourceMatch = true;
			}
		}
		
		logger.info("doesResourceMatchRequestUri:  {}", didResourceMatch);
		return didResourceMatch;
	}
	
	private boolean doesActionMatchRequestedAction(List<String> action, String method) {
		logger.debug("Permitted actions {} and requested action {}", action, method);
		
		boolean didActionMatch = false;

		for(String eachAction: action) {
			if(eachAction.equalsIgnoreCase(method)) {
				didActionMatch = true;
			}
		}
		
		logger.info("doesActionMatchRequestedAction:  {}", didActionMatch);
		return didActionMatch;
	}

	
	private boolean doesRoleMatch(List<String> role, Map<String, Object> claims) {

		logger.debug("Given roles {} in policy and user claims {}", role, claims);
		
		boolean didMatch = false;
		if(role == null || role.size() == 0) {
			logger.info("Role is not found in policy and role check evaluates to true");
			didMatch = true;
		}else {
			didMatch = doesPolicyRoleMatchUserRoles(role, claims) || doesPolicyRoleMatchEntitlements(role, claims);
		}
		
		logger.info("doesRoleMatch: {}", didMatch);
		
		return didMatch;
	}

	private boolean doesPolicyRoleMatchUserRoles(List<String> role, Map<String, Object> claims) {
		
		boolean didRoleInPolicyMatchUserRole = false;
		
		@SuppressWarnings("unchecked")
		List<String> userRoles = (List<String>) claims.get(USER_ROLE_KEY);

		if (userRoles != null && userRoles.size() > 0) {
			
			for (String eachRole: role) {
				//Check for role in either claims.userRoles or claims.entitlements
				if(userRoles.contains(eachRole)) {
					didRoleInPolicyMatchUserRole = true;
				}
			}
		}
		
		logger.info("did role match in userRoles: {}", didRoleInPolicyMatchUserRole);
		
		return didRoleInPolicyMatchUserRole;
	}


	private boolean doesPolicyRoleMatchEntitlements(List<String> role, Map<String, Object> claims) {
		
		boolean didRoleMatchEntitlement = false;
		
		@SuppressWarnings("unchecked")
		List<String> entitlements = (List<String>) claims.get(USER_ENTITLEMENTS_KEY);

		if (entitlements != null && entitlements.size() > 0) {
			
			for (String eachRole: role) {
				//Check for role in either claims.userRoles or claims.entitlements
				for(String entitlement: entitlements) {
					if(entitlement.contains(eachRole)) {
						didRoleMatchEntitlement = true;
					}
				}
			}
		}
		
		logger.info("did role match in entitlment: {}", didRoleMatchEntitlement);
		return didRoleMatchEntitlement;
	}
	
	private boolean doesConditionMatch(Map<String, Object> claims, HttpServletRequest request, AccessPolicy accessPolicy) {
		logger.debug("Evaluating condition");
		boolean didConditionMatch = false;
		
		if (accessPolicy.getCondition()== null) {
			logger.info("Condition is not found and condition check evaluates to true");
			didConditionMatch =true;
		}else {
			StandardEvaluationContext context = createExpressionEvaluationContext(claims, accessPolicy.getResource(), request.getRequestURI(), accessPolicy.getRole());
			
			if(accessPolicy.getCondition()!= null && accessPolicy.getCondition().getValue(context, Boolean.class)) {
				didConditionMatch = true;
			}
		}
		
		
		logger.info("didConditionMatch: {}", didConditionMatch);
		return didConditionMatch;
	}

	private boolean isPolicyAllowed(AccessPolicy accessPolicy) {
		return accessPolicy.getEffect().equalsIgnoreCase(ALLOW);
	}


	private List<AccessPolicy> getAllPolicies() {
		Assert.notNull(policyRepository, "Policy Repository is null");  // TODO This should never be null. If it is, spring boot should not start
		List<AccessPolicy> allPolicyRules = policyRepository.getAllAcessPoliciesByServiceId(serviceId);
		if (allPolicyRules == null) {
			logger.error("Did not find any policies for service {}", serviceId);
		}
		
		logger.debug("Number of policies retrieved for service {} - {}", serviceId, allPolicyRules.size());
		return allPolicyRules;
	}
	
	
	private StandardEvaluationContext createExpressionEvaluationContext(Map<String, Object> claims, List<String> resource, String requestUri, List<String> role) {
		StandardEvaluationContext context = new StandardEvaluationContext();
		context.setVariable(CLAIMS_KEY, claims);
		
		if(role != null && role.size()>0) {
			context.setVariable(ROLE_KEY, role);
		}
		
		Map<String, String> variables = extractPathVariables(resource, requestUri);
		
		setContextVariables(context, variables);

		logger.debug("Spring expression evaluation context: {}", context);
		return context;
	}
	
	
	private void setContextVariables(StandardEvaluationContext context, Map<String, String> variables) {
		for(String key: variables.keySet()) {
			context.setVariable(key, variables.get(key));
		}
	}

	private Map<String, String> extractPathVariables(List<String> resource, String requestUri) {
		
		Map<String, String> allVariables = new HashMap<String, String>();
		for(String eachResource: resource) {
			PathPatternParser parser = new PathPatternParser();
			PathPattern pattern = parser.parse(eachResource);
			PathPattern.PathMatchInfo matchResult = pattern.matchAndExtract(toPathContainer(requestUri));

			if(matchResult != null) {
				Map<String, String> variables = matchResult.getUriVariables();
				if (variables != null && variables.size()>0) {
					allVariables.putAll(variables);
				}
			}
		}
		
		logger.debug("Path variables added to the context {}", allVariables);
		return allVariables;
	}
	
	private PathContainer toPathContainer(String path) {
		return PathContainer.parsePath(path);
	}
}
