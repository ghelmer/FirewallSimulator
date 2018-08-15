package org.redwater.fwsim.services;

import java.util.ArrayList;
import java.util.List;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map.Entry;

import org.redwater.fwsim.exceptions.InvalidFieldValueException;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;
import org.redwater.fwsim.rules.IPRule;
import org.redwater.fwsim.rules.Rule;
import org.redwater.fwsim.rules.TCPRule;
import org.redwater.fwsim.rules.UDPRule;

public class TextRuleParser {
	/**
	 * Split the tokens array into key/value pairs.
	 * @param tokens - array of strings to split
	 * @param startOffset - starting index to split
	 * @return list of key/value pairs
	 */
	private static List<Entry<String, String>> splitPairs(String[] tokens, int startOffset) {
		ArrayList<Entry<String, String>> result = new ArrayList<>();
		for (int i = startOffset; i < tokens.length; i += 2) {
			result.add(new SimpleEntry<>(tokens[i], tokens[i + 1]));
		}
		return result;
	}

	/**
	 * Use the tokens array to build a TCP firewall rule.
	 * @param tokens - strings parsed for rule
	 * @return new TCP firewall rule
	 * @throws InvalidFieldValueException on invalid firewall rule field value
	 * @throws UnhandledFieldNameException on invalid firewall rule field name
	 */
	private static TCPRule parseTcp(String[] tokens) throws UnhandledFieldNameException, InvalidFieldValueException {
		TCPRule r = new TCPRule(splitPairs(tokens, 1));
		return r;
	}

	/**
	 * Use the tokens array to build a UDP firewall rule.
	 * @param tokens - strings parsed for rule
	 * @return new UDP firewall rule
	 * @throws InvalidFieldValueException on invalid firewall rule field value
	 * @throws UnhandledFieldNameException on invalid firewall rule field name
	 */
	private static UDPRule parseUdp(String[] tokens) throws UnhandledFieldNameException, InvalidFieldValueException {
		UDPRule r = new UDPRule(splitPairs(tokens, 1));
		return r;
	}

	/**
	 * Use the tokens array to build an IP firewall rule.
	 * @param tokens - strings parsed for rule
	 * @return new IP firewall rule
	 * @throws InvalidFieldValueException on invalid firewall rule field value
	 * @throws UnhandledFieldNameException on invalid firewall rule field name
	 */
	private static IPRule parseIp(String[] tokens) throws UnhandledFieldNameException, InvalidFieldValueException {
		IPRule r = new IPRule(splitPairs(tokens, 1));
		return r;
	}

	/**
	 * Parse the given string into a firewall rule.
	 * @param s - string specifying a rule
	 * @return new firewall rule
	 * @throws InvalidFieldValueException on invalid firewall rule field value
	 * @throws UnhandledFieldNameException on invalid firewall rule field name
	 */
	public static Rule parse(String s) throws UnhandledFieldNameException, InvalidFieldValueException {
		String[] pieces = s.split("\\s+");
		switch (pieces[0]) {
		case "ip":
			return parseIp(pieces);
		case "udp":
			return parseUdp(pieces);
		case "tcp":
			return parseTcp(pieces);
		default:
			throw new IllegalArgumentException(String.format("Invalid rule type %s", pieces[0]));
		}
	}
}
