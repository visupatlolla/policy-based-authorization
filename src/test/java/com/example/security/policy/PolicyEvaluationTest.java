package com.example.security.policy;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.example.security.policy.PolicyEvaluator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = PolicyConfiguration.class)
@TestPropertySource(properties = { "serviceId=im0183", })
public class PolicyEvaluationTest {

	String fileName = "access-policy.json";
	String jwkSUri = "https://securedev.fhlmc.com/pa/authtoken/JWKS";
	SignatureAlgorithm jwsAlgorithm = SignatureAlgorithm.ES256;
	String testJWTToken = "eyJraWQiOiI3eSIsImFsZyI6IkVTMjU2In0.eyJzdWIiOiJmNDA0MzI0IiwidXNlclJvbGVzIjpbIm1mX2RhdGFfZGVscnkiLCJtZl9jb21wYXJhYmxlc19hcHAiLCJtb2RwX2NvbXBlbmdfdG1fZ2ciLCJtZl9vbWNfYWRtaW5fZ2ciLCJtZl9jc3JtX2FkbWluX2dnIiwibW9kcF9tZmxsd21fdG1fZ2ciLCJtZl9vbWNfZGV2X2dnIiwibW9kcF9mb3VuZF9wb19nZyIsIm1vZHBfZm91bmRfdG1fZ2ciLCJtb2RwX3VuaWh1Yl90bV9nZyIsIm1vZHBfYXRsYXNzaWFuX2dnIiwibWZwY2hkbW9ucndnIiwibWZfaXJkZXZfZ2ciLCJtZm9kc2Rtb25yd2ciLCJ2ZGluX2h2aWV3X2RldjFfZ2ciLCJwZWdwX2dpdGh1Yl9nZyIsIm1mY3RzcWxnIiwibnBfc29mdHdhcmVfdG9rZW4iLCJvY3BfbWZfaW50ZWdyYXRvcl9ucF9nZyIsIm9jcF9tZl9hcHBkZXZfbnBfZ2ciLCJtZnBwbG5fdXNlcl9kZXZfZ2ciLCJlY2l0X21mX2FkbV9ucF9nZyIsIm5kbXBfY29udHJpYl9uaW1ibGVfZ2ciLCJzb2Z0d2FyZV90b2tlbiIsIm1mcHBsbl91c2VyX3Byb2RfZ2ciLCJtZl9wcm9kX3ZpcyIsIm1mcHBsbl9hZG1pbl91YXRfZ2ciLCJtZnByY2luZ191c2VyX2Rldl9nZyIsIm1mcHJjaW5nX2FkbWluX2Rldl9nZyIsIm1mc3NwbWRldmdycCIsIm1mcHJjaW5nX3VzZXJfcHJvZF9nZyIsImVtcHBhbGxnIiwiU2NyZWVuU2F2ZXJfbWFuX0dHIl0sImxhc3ROYW1lIjoiUGF0bG9sbGEiLCJmaXJzdE5hbWUiOiJWaXNod2VzaHdhciIsImF1ZCI6IkZyZWRkaWVNYWNNdWx0aWZhbWlseSIsImVtYWlsQWRkcmVzcyI6IkY0MDQzMjRARnJlZGRpZU1hYy5jb20iLCJpc3MiOiJGcmVkZGllTWFjUEFUb2tlbiIsInVzZXJUeXBlIjoiaW50ZXJuYWwiLCJleHAiOjE1ODQ4MzMyOTIsImlhdCI6MTU4NDgzMTQ4Mn0.eFmcIRS8NK_G4-KV4LndU6YSH6Il2JooL9ZrGClFVuzuJgd3dAIjwfkAkAH83hG85xdKtWdrXFz5fJSnm482bA";

	@Autowired
	private PolicyEvaluator policyEvaluator;

	String claims = "{\r\n" + "  \"sub\": \"f404324\",\r\n" + "  \"userRoles\": [\r\n"
			+ "    \"mf_comparables_app\",\r\n" + "    \"modp_compeng_tm_gg\",\r\n" + "    \"mf_omc_admin_gg\",\r\n"
			+ "    \"mfprcing_user_dev_gg\",\r\n" + "    \"mfprcing_admin_dev_gg\",\r\n" + "    \"mfsspmdevgrp\",\r\n"
			+ "    \"mfprcing_user_prod_gg\",\r\n" + "    \"emppallg\",\r\n" + "    \"ScreenSaver_man_GG\"\r\n"
			+ "  ],\r\n" + "  \"lastName\": \"LastName\",\r\n" + "  \"firstName\": \"FirstName\",\r\n"
			+ "  \"aud\": \"FreddieMacMultifamily\",\r\n" + "  \"emailAddress\": \"someid@FreddieMac.com\",\r\n"
			+ "  \"iss\": \"FreddieMacPAToken\",\r\n" + "  \"userType\": \"internal\",\r\n"
			+ "  \"exp\": 1584222193,\r\n" + "  \"iat\": 1584220383\r\n" + "}";

	String invalidClaims = "{\r\n" + "  \"sub\": \"f404324\",\r\n" + "  \"userRoles\": [\r\n"
			+ "    \"modp_compeng_tm_gg\",\r\n" + "    \"mf_omc_admin_gg\",\r\n" + "    \"mfprcing_user_dev_gg\",\r\n"
			+ "    \"mfprcing_admin_dev_gg\",\r\n" + "    \"mfsspmdevgrp\",\r\n" + "    \"mfprcing_user_prod_gg\",\r\n"
			+ "    \"emppallg\",\r\n" + "    \"ScreenSaver_man_GG\"\r\n" + "  ],\r\n"
			+ "  \"lastName\": \"LastName\",\r\n" + "  \"firstName\": \"FirstName\",\r\n"
			+ "  \"aud\": \"FreddieMacMultifamily\",\r\n" + "  \"emailAddress\": \"someid@FreddieMac.com\",\r\n"
			+ "  \"iss\": \"FreddieMacPAToken\",\r\n" + "  \"userType\": \"internal\",\r\n"
			+ "  \"exp\": 1584222193,\r\n" + "  \"iat\": 1584220383\r\n" + "}";

	String mfUserClaims = "{\r\n" + "  \"sub\": \"f404324\",\r\n" + "  \"userRoles\": [\r\n" + "    \"mf_user\",\r\n"
			+ "    \"ScreenSaver_man_GG\"\r\n" + "  ],\r\n" + "  \"lastName\": \"LastName\",\r\n"
			+ "  \"firstName\": \"FirstName\",\r\n" + "  \"aud\": \"FreddieMacMultifamily\",\r\n"
			+ "  \"emailAddress\": \"someid@FreddieMac.com\",\r\n" + "  \"iss\": \"FreddieMacPAToken\",\r\n"
			+ "  \"userType\": \"internal\",\r\n" + "  \"exp\": 1584222193,\r\n" + "  \"iat\": 1584220383\r\n" + "}";

	String mfUserClaimsWithEntitlements = "{\r\n" + "  \"sub\": \"MF101899\",\r\n" + "  \"userRoles\": [\r\n"
			+ "    \"mf_ext_ils\",\r\n" + "    \"mf_ext_dls\",\r\n" + "    \"mf_ext_hub\",\r\n"
			+ "    \"MF_Ext_LLM\"\r\n" + "  ],\r\n" + "  \"entitlements\": [\r\n"
			+ "  \"mf~Servicer:ServicingSpecialist:190334\", \r\n" + "  \"mf~Servicer:Manager:186153\",\r\n"
			+ "  \"mf~Seller:Loan Submitter:155279\"\r\n" + "  ],\r\n" + "  \"lastName\": \"Wonderland\",\r\n"
			+ "  \"firstName\": \"Alice\",\r\n" + "  \"aud\": \"FreddieMacMultifamily\",\r\n"
			+ "  \"emailAddress\": \"AWonderland@caponetest.com\",\r\n" + "  \"iss\": \"FreddieMacPAToken\",\r\n"
			+ "  \"userType\": \"external\",\r\n" + "  \"exp\": 1584723761,\r\n" + "  \"iat\": 1584721951\r\n" + "}";

	@Test
	public void testResourceAccessWithValidClaims() throws Exception {
		Map<String, Object> claimsMap = convertJSONtoMap(claims);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/comparable-service/api/v1/security/tokeninfo");
		request.setMethod("GET");

		Assert.assertTrue(policyEvaluator.check(claimsMap, request));

	}

	@Test
	public void testResourceAccessWithInValidClaims() throws Exception {
		Map<String, Object> claimsMap = convertJSONtoMap(invalidClaims);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/comparable-service/api/v1/security/tokeninfo");
		request.setMethod("GET");

		Assert.assertFalse(policyEvaluator.check(claimsMap, request));

	}

	@Test
	public void testAccessToResourceNotDefinedInPolicy() throws Exception {
		Map<String, Object> claimsMap = convertJSONtoMap(claims);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/test-service");
		request.setMethod("GET");

		Assert.assertFalse(policyEvaluator.check(claimsMap, request));

	}

	@Test
	public void testAccessToResourceWithCorrectRole() throws Exception {

		Map<String, Object> claimsMap = convertJSONtoMap(claims);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/resourcea");
		request.setMethod("GET");
		Assert.assertTrue(policyEvaluator.check(claimsMap, request));
	}

	@Test
	public void testDenyToResourceWithCorrectRole() throws Exception {

		Map<String, Object> claimsMap = convertJSONtoMap(mfUserClaims);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/resourceb");
		request.setMethod("GET");
		Assert.assertFalse(policyEvaluator.check(claimsMap, request));
	}

	@Test
	public void testAccessToResourcesWithEntitlements() throws Exception {

		Map<String, Object> claimsMap = convertJSONtoMap(mfUserClaimsWithEntitlements);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/resource/155279");
		request.setMethod("POST");
		Assert.assertTrue(policyEvaluator.check(claimsMap, request));
	}

	@Test
	public void testValidRoleinUserClaims() throws Exception {
		Boolean evalResult = evaluateConditionToCheckRolesinUserClaims(claims);
		Assert.assertTrue(evalResult);
	}

	@Test
	public void testInvalidRoleInUserClaims() throws Exception {
		Boolean evalResult = evaluateConditionToCheckRolesinUserClaims(invalidClaims);
		Assert.assertFalse(evalResult);
	}

	@Ignore
	public void testAccessControlsUsingJWTAuthenticationObject() throws Exception {
		Authentication authentication = createTestAuthentication();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("www.example.com");
		request.setRequestURI("/resourcec");
		request.setMethod("GET");
		Assert.assertTrue(policyEvaluator.check(authentication, request));

	}

	public Authentication createTestAuthentication() throws Exception {

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSUri).jwsAlgorithm(jwsAlgorithm).build();
		Jwt jwt = jwtDecoder.decode(testJWTToken);

		Authentication authentication = new JwtAuthenticationToken(jwt);

		return authentication;
	}

	private Boolean evaluateConditionToCheckRolesinUserClaims(String userCliams) throws Exception {
		String expresssion = "#claims['userRoles'].contains('mf_comparables_app')";

		Map<String, Object> claimsMap = convertJSONtoMap(userCliams);
		StandardEvaluationContext context = new StandardEvaluationContext();
		context.setVariable("claims", claimsMap);
		ExpressionParser parser = new SpelExpressionParser();

		Boolean evalResult = parser.parseExpression(expresssion).getValue(context, Boolean.class);
		return evalResult;
	}

	private Map<String, Object> convertJSONtoMap(String json) throws Exception {

		Map<String, Object> map = new HashMap<String, Object>();
		ObjectMapper mapper = new ObjectMapper();
		map = mapper.readValue(json, new TypeReference<Map<String, Object>>() {});
		return map;
	}

}
