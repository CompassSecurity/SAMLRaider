# SAML Raider - SAML2 Burp Extension

## Description

SAML Raider is a Burp Suite extension for testing SAML infrastructures. It
contains two core functionalities: Manipulating SAML Messages and manage X.509
certificates.

This software was created by Roland Bischofberger and Emanuel Duss during
a bachelor thesis at the [Hochschule für Technik
Rapperswil](https://www.hsr.ch) (HSR). Our project partner and advisor was
[Compass Security Schweiz AG](https://www.csnc.ch). We thank Compass for the
nice collaboration and support during our bachelor thesis.

## Features

The extension is divided in two parts. A SAML message editor and a certificate
management tool.

### Message Editor

Features of the SAML Raider message editor:

* Sign SAML Messages
* Sign SAML Assertions
* Remove Signatures
* Edit SAML Message
* Preview eight common XSW Attacks
* Execute eight common XSW Attacks
* Send certificate to SAMl Raider Certificate Management
* Undo all changes of a SAML Message

![Message Editor](doc/message_editor.png)

### Certificate Management

Features of the SAML Raider Certificate Management:

* Import X.509 certificates (PEM and DER format)
* Import X.509 certificate chains
* Export X.509 certificates (PEM format)
* Delete imported X.509 certificates
* Display informations of X.509 certificates
* Import private keys (PKCD#8 in DER format and traditional RSA in PEM Format)
* Export private keys (traditional RSA Key PEM Format)
* Cloning X.509 certificates
* Cloning X.509 certificate chains
* Create new X.509 certificates
* Editing and self-sign existing X.509 certificates

![Certificate Management](doc/certificate_management.png)

## Download

Download: [saml-raider-1.0.0.jar](https://github.com/SAMLRaider/SAMLRaider/releases/download/v1.0.0/saml-raider-1.0.0.jar)

## Installation

Start the Burp Suite and click at the `Extender` tab on `Add`. Choose the SAML
Raider JAR file to install the extension.


## Usage

To test SAML environments more comfortable, you could add a intercept rule in
the proxy settings. Add a new rule which checks if a Parameter Name
`SAMLResponse` is in the request. We hope the usage of our extension is mostly
self explaining :smile:.

## Build

Clone the repository and build the JAR file using Maven:

    $ mvn install

Use the JAR file in `target/saml-raider-1.0-SNAPSHOT-jar-with-dependencies.jar`
as a Burp extension.

## Bachelor Thesis

As soon as our thesis is online, we will publish the link here.

## License

See the [LICENSE](LICENSE) file (MIT License) for license rights and
limitations.

## Authors

* Roland Bischofberger (GitHub: [RouLee](https://github.com/RouLee))
* Emanuel Duss (GitHub: [mindfuckup](https://github.com/mindfuckup))
