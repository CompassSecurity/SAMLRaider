package gui;

import burp.BurpExtender;
import burp.api.montoya.ui.Theme;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.io.Serial;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;

/**
 * XML editor with syntax highlighting, backed by RSyntaxTextArea.
 * Uses a plain JScrollPane (not RTextScrollPane) to avoid focus/input
 * conflicts inside Burp's Swing environment.
 */
public class SamlXmlEditor extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private final RSyntaxTextArea textArea;
    private final AtomicBoolean modified = new AtomicBoolean(false);
    private volatile boolean suppressModified = false;

    public SamlXmlEditor() {
        super(new BorderLayout());

        // Ensure RSyntaxTextArea can load its internal resources through
        // Burp's plugin ClassLoader.
        ClassLoader origCL = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(RSyntaxTextArea.class.getClassLoader());

        try {
            textArea = new RSyntaxTextArea(20, 80);
            textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            textArea.setCodeFoldingEnabled(false); // requires RTextScrollPane — skip it
            textArea.setAntiAliasingEnabled(true);
            textArea.setBracketMatchingEnabled(true);
            textArea.setAutoIndentEnabled(true);
            textArea.setMarkOccurrences(true);
            textArea.setTabsEmulated(true);
            textArea.setTabSize(2);
            textArea.setEditable(true);
            textArea.setEnabled(true);
            textArea.setFocusable(true);
        } finally {
            Thread.currentThread().setContextClassLoader(origCL);
        }

        // Match Burp's editor font
        Font burpFont = BurpExtender.api.userInterface().currentEditorFont();
        if (burpFont != null) {
            textArea.setFont(burpFont);
        }

        applyBurpTheme();

        // Track modifications
        textArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { onChange(); }
            @Override public void removeUpdate(DocumentEvent e)  { onChange(); }
            @Override public void changedUpdate(DocumentEvent e) { onChange(); }
            private void onChange() {
                if (!suppressModified) {
                    modified.set(true);
                }
            }
        });

        // Plain JScrollPane — avoids the focus/input issues that
        // RTextScrollPane causes inside Burp's component hierarchy.
        var scroll = new JScrollPane(textArea);
        scroll.setBorder(null);
        add(scroll, BorderLayout.CENTER);
    }

    private void applyBurpTheme() {
        Theme theme = BurpExtender.api.userInterface().currentTheme();

        if (theme == Theme.DARK) {
            textArea.setBackground(new Color(0x1E1F22));
            textArea.setForeground(new Color(0xD6D6D6));
            textArea.setCaretColor(new Color(0xEDEDED));
            textArea.setSelectionColor(new Color(0x264F78));
            textArea.setCurrentLineHighlightColor(new Color(0x2A2D2E));
        } else {
            textArea.setBackground(Color.WHITE);
            textArea.setForeground(new Color(0x1F2328));
            textArea.setCaretColor(Color.BLACK);
            textArea.setSelectionColor(new Color(0xBBDDFF));
            textArea.setCurrentLineHighlightColor(new Color(0xF2F6FF));
        }

        textArea.setFadeCurrentLineHighlight(true);
        textArea.setLineWrap(false);
        textArea.setMarginLineEnabled(false);
    }

    public void setText(String text) {
        suppressModified = true;
        try {
            textArea.setText(Objects.requireNonNullElse(text, ""));
            textArea.setCaretPosition(0);
            modified.set(false);
        } finally {
            suppressModified = false;
        }
    }

    public String getText() {
        return textArea.getText();
    }

    public void setEditable(boolean editable) {
        textArea.setEditable(editable);
        textArea.setEnabled(true);
        textArea.setFocusable(true);
    }

    public boolean isModified() {
        return modified.get();
    }

    public void resetModified() {
        modified.set(false);
    }

    public String selectedText() {
        return textArea.getSelectedText();
    }
}
