package com.example.security.policy;

import java.util.List;

import javax.validation.constraints.NotNull;

import org.springframework.expression.Expression;

public class AccessPolicy {
	
	@NotNull
	private List<String> resource;
	@NotNull
	private List<String> action; 
	private List<String> role;
	private Expression  condition;
	@NotNull
	private String effect;
	
	public List<String> getRole() {
		return role;
	}
	public void setRole(List<String> role) {
		this.role = role;
	}
	public String getEffect() {
		return effect;
	}
	public void setEffect(String effect) {
		this.effect = effect;
	}
	public List<String> getResource() {
		return resource;
	}
	public void setResource(List<String> resource) {
		this.resource = resource;
	}
	public List<String> getAction() {
		return action;
	}
	public void setAction(List<String> action) {
		this.action = action;
	}
	public Expression getCondition() {
		return condition;
	}
	public void setCondition(Expression condition) {
		this.condition = condition;
	}
	
	
}
