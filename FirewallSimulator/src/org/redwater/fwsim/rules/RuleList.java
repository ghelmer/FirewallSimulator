package org.redwater.fwsim.rules;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.Packet;
import org.redwater.fwsim.exceptions.InvalidFieldValueException;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;
import org.redwater.fwsim.services.TextRuleParser;

/**
 * Maintain a list of firewall rules, and execute rules on a packet. 
 * @author ghelmer
 */
public class RuleList {
	private List<IRule> rules;

	/**
	 * Construct a new RuleList.
	 */
	public RuleList() {
		rules = new ArrayList<>();
	}
	
	/**
	 * Parse and add a new rule to the list.
	 * @return newly parsed rule
	 * @throws InvalidFieldValueException on invalid rule field value
	 * @throws UnhandledFieldNameException on invalid rule field name
	 */
	public IRule addRule(String s) throws UnhandledFieldNameException, InvalidFieldValueException {
		IRule r = TextRuleParser.parse(s);
		rules.add(r);
		return r;
	}

	/**
	 * Check this packet against the list of rules. Return the first
	 * rule that matches, or null if none.
	 * @param packet - Packet to check against this rule.
	 * @return IRule object that matched the package, or null
	 */
	public IRule checkRules(Packet packet) {
		for (IRule r : rules) {
			if (r.matchesRule(packet)) {
				return r;
			}
		}
		return null;
	}
}
