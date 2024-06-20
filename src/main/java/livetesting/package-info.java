/**
 * Burp's Montoya API consist of only interfaces. Concrete implementation to those interfaces are only available during runtime.
 * This makes unit testing hard. That is why this package exists. It enables the developer to write tests and execute them
 * in the "SAML Raider Live Testing" tab when in debug mode. This is useful when hunting and reproducing bugs. In future
 * it should  also give more confidence that things still work after refactoring.
 * <br>
 * <br>
 * In order to write new tests, create a new class that ends with "Test", like "MyTest.java". For each test case write a
 * public method with no parameters that returns a "TestResult". The LiveTestingTab will automatically search for such methods,
 * invoke, check and present the results in the GUI.
 */
package livetesting;