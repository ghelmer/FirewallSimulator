package org.redwater.fwsim.services.tests;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.redwater.fwsim.exceptions.InvalidFieldValueException;
import org.redwater.fwsim.exceptions.UnhandledFieldNameException;
import org.redwater.fwsim.services.TextRuleParser;

public class TextRuleParserTest {

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void test() {
		try {
			TextRuleParser.parse("udp srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0  srcPort 25 dstPort 0-65535 action accept");
		} catch (UnhandledFieldNameException | InvalidFieldValueException e) {
			e.printStackTrace();
			fail("UDP rule parse failed");
		}
		try {
			TextRuleParser.parse("tcp srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0 srcPort 25 dstPort 0-65535 action accept");
		} catch (UnhandledFieldNameException | InvalidFieldValueException e) {
			e.printStackTrace();
			fail("TCP rule parse failed");
		}
		try {
			TextRuleParser.parse("ip srcAddress 192.168.1.0/24 dstAddress 0.0.0.0/0 action accept");
		} catch (UnhandledFieldNameException | InvalidFieldValueException e) {
			e.printStackTrace();
			fail("IP rule parse failed");
		}
	}
}
