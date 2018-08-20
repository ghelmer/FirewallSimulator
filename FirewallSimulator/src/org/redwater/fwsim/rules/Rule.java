package org.redwater.fwsim.rules;

import java.util.List;
import java.util.Map.Entry;

import org.pcap4j.packet.Packet;
import org.redwater.fwsim.exceptions.InvalidFieldValueException;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;

/**
 * Base class for a rule that matches packets.
 * @author ghelmer
 */
public class Rule implements IRule {
	private RuleActions ruleAction;
	private String metadata;

	public Rule () {
		ruleAction = null;
		metadata = "";
	}
	
	/**
	 * Construct a Rule using the list of fields and values.
	 * @throws UnhandledFieldNameException 
	 */
	public Rule(List<Entry<String, String>> parameters) throws UnhandledFieldNameException, InvalidFieldValueException {
		for (Entry<String, String> e : parameters) {
			setRuleField(e.getKey(), e.getValue());
		}
	}
	
	/**
	 * Action access method..
	 * @param packet - packet to check
	 * @return action assigned to rule
	 */
	public RuleActions getAction(Packet packet) {
		return ruleAction;
	}
	
	/**
	 * Default rule match method. Always succeeds.
	 * @param packet - packet to check
	 * @return true
	 */
	public boolean matchesRule(Packet packet) {
		return true;
	}

	/**
	 * Default rule field set method implementation. Always throws exception.
	 * @param fieldName - name of rule field to set
	 * @param value - value to use for field
	 * @throws UnhandledFieldNameException always
	 */
	public void setRuleField(String fieldName, String value) throws UnhandledFieldNameException, InvalidFieldValueException {
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
	
	/**
	 * Set metadata for a rule (such as the number in the list of rules).
	 * @param metadata - arbitrary string data
	 */
	public void setRuleMetadata(String info) {
		metadata = info;
	}

	/**
	 * Get metadata from a rule (such as the number in the list of rules).
	 * @return metadata - arbitrary string data
	 */
	public String getRuleMetadata() {
		return metadata;
	}
	
	/**
	 * Return a text representation of this rule.
	 * @return text
	 */
	public String toString() {
		switch (ruleAction) {
		case ACCEPT:
			return String.format("%s action accept", metadata);
		case DENY:
			return String.format("%s action deny", metadata);
		case REJECT:
			return String.format("%s action reject", metadata);
		default:
			return String.format("%s action INVALID", metadata);
		}
	}
}
