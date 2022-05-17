## Development

### Burp Extender API

The Burp Extender API can be found here:
https://portswigger.net/burp/extender/api/index.html.

### Build

Clone the project into your workspace:

    git clone https://github.com/SAMLRaider/SAMLRaider.git

Import existing project into your Eclipse workspace: `File` → `Import...` →
`Existing Projects into Workspace`. Select the cloned folder and press `Finish`.

[Download](https://portswigger.net/burp/download.html) the latest version of
Burp Suite as a JAR file and place it in the `lib` folder.

Add the Burp Suite JAR file to the libraries: Rightclick on Project →
`Properties` → `Java Build Path` → `Libraries` and add the JAR file.

Install `maven` so you can build SAMLRaider using the build automation tool
Maven:

    $ mvn install

You can also build it without executing the tests:

    $ mvn install -Dmaven.test.skip=true

Load the Burp Extension into Burp: `Extender` → `Add` → select the JAR file
(with dependencies) in the `./target` directory of the project, like
`./target/saml-raider-$VERSION-SNAPSHOT-jar-with-dependencies.jar`.

Then you can test the extension and rebuild it again after a change.

Tipp: To reload the extension in Burp, without restarting Burp, hit the `Ctrl`
key and click on the checkbox next to the extension in the `Extender` tab.

### Run SAML Raider inside Eclipse

To start the Extension directly from Eclipse, import the Repository into
Eclipse. You can directly import a existing Maven Project. Note that the
Eclipse Maven Plugin `m2e` is required. This is included in the latest "Eclipse
IDE for Java Developers".

Place the Burp Suite JAR file into the `lib` folder and add the Burp JAR as
a Library in the Eclipse Project (`Properties` → `Build Path` → `Libraries`).

Open the Burp JAR under `Referenced Libraries` in the Package Explorer and
right click in the Package `burp` on `StartBurp.class` and select `Run As...` →
`Java Application` to start Burp and load the Extension automatically.  (Or in
Eclipse: `Run` → `Debug As` → `Java Application` → `StartBurp - burp` → `OK`.)

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
