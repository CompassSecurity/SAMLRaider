## Development

### Burp Extender API

The Burp Extender API can be found here:
https://portswigger.net/burp/extender/api/index.html.

### Build

Linux:

```shell
./gradlew clean build fatJar
```

Windows: 

```shell
.\gradlew.bat clean build fatJar
```

Get the jar from `build/libs/saml-raider-<version>.jar`

Load the Burp Extension into Burp: `Extensions` → `Add` → select the JAR file

Then you can test the extension and rebuild it again after a change.

Tipp: To reload the extension in Burp, without restarting Burp, hit the `Ctrl`
key and click on the checkbox next to the extension in the `Extensions` tab.

### Debug Mode

To enable the Debug Mode, set the `DEBUG` Flag in the Class `Flags` from the
Package `helpers` to `true`. This will write all output to the
`SAMLRaiderDebug.log` logfile and load example certificates for testing.

### Debugging

Start Burp with the Java Debug Wire Protocol (JWDP) server:

```
$ java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar burpsuite_community_*.jar
```

Attach the your IDE to the debugger. In IntelliJ:

- Run → Edit Configurations
- New Configuration: Remote JVM Debug (apply defaults)

Attach your IDE to the running Burp process:

- Run → Debug "Burp"

Build the extension, load the JAR into Burp, set breakpoints and start debugging.

Check out the following article for more information: 
https://www.netspi.com/blog/technical/web-application-penetration-testing/debugging-burp-extensions/

### Test with fake SAML Response

To send a SAML Response to Burp, you can use the script `samltest` in the
`scripts/samltest` directory. It sends the SAML Response from `saml_response`
to Burp (`localhost:8080`) and prints out the modified response from our
plugin. You have to install `gawk` (GNU awk) as `awk` and `libxml2-utils` for
the `xmllint` command.
