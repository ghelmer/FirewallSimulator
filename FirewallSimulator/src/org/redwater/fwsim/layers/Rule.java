package org.redwater.fwsim.layers;

import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.net.util.SubnetUtils;
import org.pcap4j.packet.Packet;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;

/**
 * Base class for a rule that matches packets.
 * @author ghelmer
 */
public class Rule implements IRule {
	protected RuleActions ruleAction;

	public Rule () {
		ruleAction = null;
	}
	
	/**
	 * Construct a Rule using the list of fields and values.
	 * @throws UnhandledFieldNameException 
	 */
	public Rule(List<Entry<String, String>> parameters) throws UnhandledFieldNameException {
		for (Entry<String, String> e : parameters) {
			setRuleField(e.getKey(), e.getValue());
		}
	}
	
	/**
	 * Default action access method. Always fails.
	 * @param packet - packet to check
	 * @return null
	 */
	public RuleActions getAction(Packet packet) {
		return null;
	}
	
	/**
	 * Default rule match method. Always fails.
	 * @param packet - packet to check
	 * @return false
	 */
	public boolean matchesRule(Packet packet) {
		return false;
	}

	/**
	 * Default rule field set method implementation. Always throws exception.
	 * @param fieldName - name of rule field to set
	 * @param value - value to use for field
	 * @throws UnhandledFieldNameException always
	 */
	public void setRuleField(String fieldName, String value) throws UnhandledFieldNameException {
		switch (fieldName) {
		case "action":
			ruleAction = actionToRuleAction(value);
			break;
		default:
			throw new UnhandledFieldNameException(String.format("Unhandled field name: %s", fieldName));
		}
	}
	
	/**
	 * Helper method to get the RuleAction from the given string.
	 * @throws UnhandledFieldNameException on invalid action
	 */
	public static RuleActions actionToRuleAction(String action) throws UnhandledFieldNameException {
		switch (action) {
		case "accept":
			return RuleActions.ACCEPT;
		case "deny":
			return RuleActions.DENY;
		case "reject":
			return RuleActions.REJECT;
		}
		throw new UnhandledFieldNameException(String.format("Invalid rule action %s", action));
	}
}
