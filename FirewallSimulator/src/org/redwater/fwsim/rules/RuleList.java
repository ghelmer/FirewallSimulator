package org.redwater.fwsim.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

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
	 * Parse a list of Strings into rules.
	 * @throws InvalidFieldValueException 
	 * @throws UnhandledFieldNameException 
	 */
	public void parse(List<String> strings) throws UnhandledFieldNameException, InvalidFieldValueException {
		for (String s : strings) {
			addRule(s);
		}
	}
	
	/**
	 * Parse lines from an input stream into rules. Comments begin with '#'.
	 * Add metadata to each rule indicating the source line number.
	 * @throws InvalidFieldValueException 
	 * @throws UnhandledFieldNameException 
	 */
	public void parse(Scanner in) throws UnhandledFieldNameException, InvalidFieldValueException {
		int line = 0;
		while (in.hasNextLine()) {
			line++;
			String s = in.nextLine();
			
			// Trim lines at # (used for comments).
			int hashIndex = s.indexOf('#');
			if (hashIndex != -1) {
				s = s.substring(0,  hashIndex);
			}
			
			// Skip empty lines.
			s = s.trim();
			if (s.length() == 0) {
				continue;
			}
			
			// Parse the remaining string, and set a default metadata.
			IRule r = addRule(s);
			r.setRuleMetadata(String.format("Line %d", line));
		}
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
