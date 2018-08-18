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

	public Rule () {
		ruleAction = null;
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
	 * Return a text representation of this rule.
	 * @return text
	 */
	public String toString() {
		switch (ruleAction) {
		case ACCEPT:
			return "action accept";
		case DENY:
			return "action deny";
		case REJECT:
			return "action reject";
		default:
			return "action INVALID";
		}
	}
}
