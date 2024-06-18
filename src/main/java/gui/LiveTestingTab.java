package gui;

import burp.BurpExtender;
import com.google.common.reflect.ClassPath;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.border.EmptyBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import livetesting.TestOrder;
import livetesting.TestResult;

public class LiveTestingTab extends JPanel {

    public LiveTestingTab() {
        setBorder(new EmptyBorder(10, 10, 10, 10));
        var textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setBackground(Color.BLACK);
        textPane.setForeground(Color.WHITE);
        textPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));

        var button = new JButton("Run tests");

        setLayout(new BorderLayout(10, 10));
        add(new JScrollPane(textPane), BorderLayout.CENTER);
        add(button, BorderLayout.SOUTH);

        button.addActionListener(listener -> {
            textPane.setText("");

            var document = textPane.getStyledDocument();

            var inRed = new SimpleAttributeSet();
            inRed.addAttribute(StyleConstants.Foreground, Color.RED);

            var inGreen = new SimpleAttributeSet();
            inGreen.addAttribute(StyleConstants.Foreground, Color.GREEN);

            try {
                var classLoader = this.getClass().getClassLoader();

                var testClasses =
                        ClassPath.from(classLoader)
                                .getTopLevelClassesRecursive("livetesting")
                                .stream()
                                .filter(classInfo -> classInfo.getName().endsWith("Test"))
                                .map(ClassPath.ClassInfo::load)
                                .collect(Collectors.toSet());

                for (var testClass : testClasses) {
                    document.insertString(document.getLength(), "%s\n".formatted(testClass.getSimpleName()), null);
                    var testInstance = testClass.getDeclaredConstructor().newInstance();

                    var testMethods = Arrays.stream(testClass.getDeclaredMethods())
                            .filter(method -> method.canAccess(testInstance))
                            .filter(method -> method.getReturnType().equals(TestResult.class))
                            .sorted((testMethodA, testMethodB) -> {
                                var orderA = testMethodA.getAnnotation(TestOrder.Order.class);
                                var orderB = testMethodB.getAnnotation(TestOrder.Order.class);
                                return TestOrder.comparator().compare(orderA, orderB);
                            })
                            .toList();

                    for (var testMethod : testMethods) {
                        document.insertString(document.getLength(), "  %s... ".formatted(testMethod.getName()), null);
                        var result = (TestResult) testMethod.invoke(testInstance);
                        var styling = result.success() ? inGreen : inRed;
                        document.insertString(
                                document.getLength(),
                                result.success() ? "success" : "failed",
                                styling);
                        if (result.message() != null) {
                            document.insertString(
                                    document.getLength(),
                                    "\n%s".formatted(result.message()),
                                    styling);
                        }
                        if (result.throwable() != null) {
                            var byteArrayOutputStream = new ByteArrayOutputStream();
                            var printStream = new PrintStream(byteArrayOutputStream);
                            result.throwable().printStackTrace(printStream);
                            document.insertString(
                                    document.getLength(),
                                    "\n%s".formatted(byteArrayOutputStream.toString()),
                                    styling);
                        }
                        document.insertString(document.getLength(), "\n", null);
                    }
                }
            } catch (Exception exc) {
                BurpExtender.api.logging().logToError(exc);
                var byteArrayOutputStream = new ByteArrayOutputStream();
                var printStream = new PrintStream(byteArrayOutputStream);
                exc.printStackTrace(printStream);
                try {
                    document.insertString(
                            document.getLength(),
                            "\n%s".formatted(byteArrayOutputStream.toString()),
                            inRed);
                } catch (BadLocationException exc1) {
                    BurpExtender.api.logging().logToError(exc1);
                }
            }
        });
    }

    public String caption() {
        return "SAML Raider Live Testing";
    }
}
