package gui;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import java.awt.BorderLayout;
import java.io.Serial;
import javax.swing.JPanel;

/**
 * Thin wrapper around Burp's native RawEditor that exposes a simple
 * String-based API.  Burp's editor handles theming, editability, and
 * basic syntax colouring automatically.
 */
public class SamlXmlEditor extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private final RawEditor rawEditor;

    public SamlXmlEditor() {
        super(new BorderLayout());
        rawEditor = BurpExtender.api.userInterface().createRawEditor();
        add(rawEditor.uiComponent(), BorderLayout.CENTER);
    }

    public void setText(String text) {
        rawEditor.setContents(ByteArray.byteArray(text != null ? text : ""));
    }

    public String getText() {
        return rawEditor.getContents().toString();
    }

    public void setEditable(boolean editable) {
        rawEditor.setEditable(editable);
    }

    public boolean isModified() {
        return rawEditor.isModified();
    }

    public void resetModified() {
        // RawEditor resets its modified flag when setContents is called,
        // so re-set the current contents to clear it.
        rawEditor.setContents(rawEditor.getContents());
    }

    public String selectedText() {
        return rawEditor.selection()
                .map(sel -> sel.contents().toString())
                .orElse(null);
    }
}
