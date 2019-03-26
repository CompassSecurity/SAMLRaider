package application;

import helpers.HTTPHelpers;
import org.junit.Test;

import java.io.IOException;
import java.util.Base64;
import java.util.zip.DataFormatException;

import static org.junit.Assert.assertEquals;

public class HTTPHelpersTest {
	HTTPHelpers helpers = new HTTPHelpers();

	String compressed = "fVLLasMwEPwVo3siWXb8EI6hNJdAemlCDr0UPdaNwZaEV4J+fh2H0gRKTmJ3NLOzIzUox8GLg/tyMbwDemcRku9xsCgWaEviZIWT2KOwcgQUQYvjy9tB8DUTfnLBaTeQO8pzhkSEKfTOkmS/25LPQmpV6jwtOYNu0zGmc53xrmBpoVVWm7JLNatlVVUkOcOEM3NLZqGZjhhhbzFIG+YWSzcrVq7S+pRmIssF4x8k2QGG3sqwsC4heEHp1WOEAT3FfvQDXGs6OhMHWPuLX3CKt5OvhiWZBTDQyTiEFfp5uP0N6+TmLWpeVEqV3DCjeJ5DV9baZGxub8CAUgagLE2t6oq0zVVYLO6n9tFTb3xD7+Hm9jzHIEPEx+rVGUjOcqY9DxyX2+IYtQZEQtvbhD9R+t8XaH8A";
	String decompressed = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_6acb7c41720ef5f00c4c32f6016cb39d7f1c09a888\" Version=\"2.0\" IssueInstant=\"2015-07-19T13:34:02Z\" Destination=\"http://samluelsp/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp\" InResponseTo=\"_9268bb72d0db244ef79cd309265edebbdee77d9b98\"><saml:Issuer>http://samluelidp</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status></samlp:LogoutResponse>";
	
	@Test
	public void testInflate() throws IOException, DataFormatException {
		byte[] valueDecoded = Base64.getDecoder().decode(compressed);
		assertEquals(decompressed, new String(helpers.decompress(valueDecoded, true), "UTF-8"));
	}
	
	@Test
	public void testDeflate() throws IOException {
		byte [] valueCompressed = helpers.compress(decompressed.getBytes("UTF-8"), true);
		String result = Base64.getEncoder().encodeToString(valueCompressed);
		result = result.replaceAll("\\r?\\n", "");
		assertEquals(compressed, result);
	}
	
}
