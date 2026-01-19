from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from javax.swing import JTextArea, JScrollPane, JMenuItem, JPanel, JLabel, JTextField, JSplitPane, SwingConstants, JTabbedPane, SwingUtilities, JComboBox, JButton
from javax.swing.event import DocumentListener, CaretListener
from javax.swing.text import DefaultHighlighter
from java.awt import BorderLayout, Dimension, Font, FlowLayout
from java.util import ArrayList
from java.lang import String
import re
import traceback
import json
import os

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Regex Extractor")

        self.presets = {}
        self._load_config()

        # UI Components
        self._init_ui()
        
        callbacks.registerContextMenuFactory(self)
        
        callbacks.addSuiteTab(self)
        
        # Defer setting the divider location until after the UI is rendered
        SwingUtilities.invokeLater(lambda: self._split_pane.setDividerLocation(0.5))
        
        print("Regex Extractor extension loaded.")

    def _load_config(self):
        try:
            # 1. Try to resolve path dynamically using __file__
            # Use os.path.abspath to ensure we handle relative paths correctly
            if '__file__' in globals():
                script_path = os.path.abspath(__file__)
                base_dir = os.path.dirname(script_path)
            else:
                base_dir = os.getcwd()

            config_path = os.path.join(base_dir, "regex_config.json")
            print("DEBUG: Computed config path: " + config_path)

            # 2. Fallback: If computed path doesn't exist, try the user's known workspace path
            # This is helpful if Jython execution context messes up __file__
            if not os.path.exists(config_path):
                print("DEBUG: Config not found at computed path.")
                known_path = "/Users/k/Desktop/red/plug/regex_config.json"
                if os.path.exists(known_path):
                    config_path = known_path
                    print("DEBUG: Found config at known path: " + config_path)

            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    self.presets = json.load(f)
                print("DEBUG: Config loaded successfully. Defined presets: " + str(self.presets.keys()))
            else:
                print("ERROR: Config file not found at " + config_path)
                
        except Exception as e:
            print("ERROR loading config: " + str(e))
            traceback.print_exc()


    def _init_ui(self):
        # Left side: Response Data (with Search)
        self._left_panel = JPanel(BorderLayout())
        
        # Search Panel
        # Search Panel
        search_panel = JPanel(BorderLayout())
        search_label = JLabel("Search: ")
        self._search_field = JTextField()
        self._search_field.getDocument().addDocumentListener(RegexListener(self._update_search_highlights))
        
        # Search Navigation Buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self._btn_prev = JButton("<", actionPerformed=self._search_prev)
        self._btn_next = JButton(">", actionPerformed=self._search_next)
        btn_panel.add(self._btn_prev)
        btn_panel.add(self._btn_next)

        search_panel.add(search_label, BorderLayout.WEST)
        search_panel.add(self._search_field, BorderLayout.CENTER)
        search_panel.add(btn_panel, BorderLayout.EAST)

        self._response_area = JTextArea()
        self._response_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._response_area.setLineWrap(True)
        self._response_area.addCaretListener(self._on_response_selection)

        self._response_scroll = JScrollPane(self._response_area)
        self._response_scroll.setPreferredSize(Dimension(500, 400))
        
        self._left_panel.add(search_panel, BorderLayout.NORTH)
        self._left_panel.add(self._response_scroll, BorderLayout.CENTER)
        
        # Right side: Regex Input and Matches
        self._regex_panel = JPanel(BorderLayout())
        self._regex_panel.setPreferredSize(Dimension(500, 400))
        
        # Top Container for Input and Presets
        top_container = JPanel(BorderLayout())

        # Regex Input Area
        input_panel = JPanel(BorderLayout())
        input_label = JLabel("Regex Pattern: ")
        self._regex_field = JTextField()
        self._regex_field.getDocument().addDocumentListener(RegexListener(self._update_matches))
        input_panel.add(input_label, BorderLayout.WEST)
        input_panel.add(self._regex_field, BorderLayout.CENTER)
        
        # Preset Quick Select
        preset_panel = JPanel(FlowLayout(FlowLayout.RIGHT))

        self._btn_dedup = JButton("Deduplicate", actionPerformed=self._deduplicate_matches)
        preset_panel.add(self._btn_dedup)
        
        preset_label = JLabel("Quick Select: ")
        
        preset_keys = sorted(self.presets.keys())
        preset_items = ["-- Select Preset --"] + preset_keys
        self._preset_combo = JComboBox(preset_items)
        self._preset_combo.addActionListener(self._on_preset_change)
        
        preset_panel.add(preset_label)
        preset_panel.add(self._preset_combo)

        top_container.add(input_panel, BorderLayout.CENTER)
        top_container.add(preset_panel, BorderLayout.EAST)

        # Matches Area (Center of Right Panel)
        self._matches_area = JTextArea()
        self._matches_area.setEditable(False)
        self._matches_area.setFont(Font("Monospaced", Font.PLAIN, 12)) 
        self._matches_scroll = JScrollPane(self._matches_area)
        
        self._regex_panel.add(top_container, BorderLayout.NORTH)
        self._regex_panel.add(self._matches_scroll, BorderLayout.CENTER)

        # Split Pane
        self._split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._left_panel, self._regex_panel)
        self._split_pane.setResizeWeight(0.5)

    def _deduplicate_matches(self, event):
        content = self._matches_area.getText()
        if not content or content == "No matches found." or content.startswith("Regex Error:"):
            return
            
        lines = content.split('\n')
        seen = set()
        deduped = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                deduped.append(line)
        
        self._matches_area.setText('\n'.join(deduped))
        self._matches_area.setCaretPosition(0)

    def _on_preset_change(self, event):
        selected = self._preset_combo.getSelectedItem()
        if selected and selected in self.presets:
            self._regex_field.setText(self.presets[selected])


    # ITab implementation
    def getTabCaption(self):
        return "Regex Extractor"

    def getUiComponent(self):
        return self._split_pane

    # IContextMenuFactory implementation
    
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Regex Extractor", actionPerformed=lambda x: self._send_to_extractor(invocation)))
        return menu_list

    def _send_to_extractor(self, invocation):
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            return

        # Use the first selected message
        message_info = selected_messages[0]
        
        # Prefer response, fallback to request
        data_bytes = message_info.getResponse()
        is_response = True
        if not data_bytes:
            data_bytes = message_info.getRequest()
            is_response = False
        
        if not data_bytes:
            return

        # Analyze to split headers and body
        if is_response:
            analyzed = self._helpers.analyzeResponse(data_bytes)
        else:
            analyzed = self._helpers.analyzeRequest(data_bytes)
        
        offset = analyzed.getBodyOffset()
        
        # Extract Headers
        header_bytes = data_bytes[:offset]
        header_str = self._helpers.bytesToString(header_bytes)
        
        # Extract Body
        body_bytes = data_bytes[offset:]
        try:
            # Force UTF-8 decoding for proper Chinese character display
            body_str = String(body_bytes, "UTF-8")
        except Exception:
            body_str = self._helpers.bytesToString(body_bytes)
        
        # Format Body (JS/JSON)
        formatted_body = self._try_format_data(unicode(body_str), message_info)
        
        # Combine Header and Formatted Body
        full_text = header_str + formatted_body
        self._response_area.setText(full_text)
        
        self._update_matches(None)
        
        # Highlight the tab
        SwingUtilities.invokeLater(self._switch_to_me)

    def _switch_to_me(self):
        # Walk up the component tree to find the JTabbedPane
        parent = self._split_pane.getParent()
        while parent:
            if isinstance(parent, JTabbedPane):
                for i in range(parent.getTabCount()):
                    # Check if our component is inside this tab
                    tab_component = parent.getComponentAt(i)
                    if SwingUtilities.isDescendingFrom(self._split_pane, tab_component) or tab_component == self._split_pane:
                        parent.setSelectedIndex(i)
                        return
            parent = parent.getParent()

    def _update_matches(self, event):
        data = self._response_area.getText()
        pattern = self._regex_field.getText()
        
        if not data or not pattern:
            self._matches_area.setText("")
            return

        try:
            matches = re.findall(pattern, data, re.MULTILINE | re.DOTALL)
            if matches:
                 # Clean up display for groups
                formatted_matches = []
                for m in matches:
                    if isinstance(m, tuple):
                        # Convert each group item to unicode string
                        formatted_matches.append(u", ".join(unicode(x) for x in m))
                    else:
                        # Use unicode() instead of str() to avoid ascii encoding error on Python 2
                        formatted_matches.append(unicode(m))
                self._matches_area.setText(u"\n".join(formatted_matches))
                self._matches_area.setCaretPosition(0)
            else:
                self._matches_area.setText("No matches found.")
        except Exception as e:
            self._matches_area.setText("Regex Error: " + str(e))

    def _on_response_selection(self, event):
        selected_text = self._response_area.getSelectedText()
        if selected_text:
            # Escape regex special characters so the selection matches literally
            escaped_text = re.escape(selected_text)
            
            current_pattern = self._regex_field.getText()
            if escaped_text != current_pattern:
                 self._regex_field.setText(escaped_text)

    def _update_search_highlights(self, event):
        term = self._search_field.getText()
        highlighter = self._response_area.getHighlighter()
        highlighter.removeAllHighlights()
        
        self._search_matches = []
        self._current_match_index = -1
        
        if not term or len(term) == 0:
            return
            
        content = self._response_area.getText()
        if not content:
            return
            
        try:
            index = 0
            while True:
                index = content.find(term, index)
                if index == -1:
                    break
                
                self._search_matches.append(index)
                try:
                    highlighter.addHighlight(index, index + len(term), DefaultHighlighter.DefaultPainter)
                except:
                    pass
                index += len(term)
            
            # Auto-scroll to first match
            if self._search_matches:
                self._current_match_index = 0
                self._scroll_to_match(0)
                
        except:
             pass

    def _search_next(self, event):
        if not hasattr(self, '_search_matches') or not self._search_matches:
            return
        self._current_match_index = (self._current_match_index + 1) % len(self._search_matches)
        self._scroll_to_match(self._current_match_index)

    def _search_prev(self, event):
        if not hasattr(self, '_search_matches') or not self._search_matches:
            return
        self._current_match_index = (self._current_match_index - 1 + len(self._search_matches)) % len(self._search_matches)
        self._scroll_to_match(self._current_match_index)

    def _scroll_to_match(self, idx):
        if idx < 0 or idx >= len(self._search_matches):
            return
        
        pos = self._search_matches[idx]
        term_len = len(self._search_field.getText())
        
        # Select the match to highlight it and ensure it's visible
        self._response_area.setCaretPosition(pos)
        self._response_area.select(pos, pos + term_len)
        self._response_area.grabFocus()
        self._search_field.grabFocus() # Return focus to search field so user can keep typing

    def _try_format_data(self, data, message_info):
        # 1. Determine Type
        response = message_info.getResponse()
        is_json = False
        is_script = False
        
        if response:
            analyzed = self._helpers.analyzeResponse(response)
            mime = analyzed.getInferredMimeType()
            
            if mime == "JSON":
                is_json = True
            elif mime == "script":
                is_script = True
            
            # Additional check: Look at Content-Type header explicitly
            # because "inferred" might be generic
            if not is_json and not is_script:
                for h in analyzed.getHeaders():
                    h_lower = h.lower()
                    if "content-type:" in h_lower:
                        if "json" in h_lower:
                            is_json = True
                        if "javascript" in h_lower or "ecmascript" in h_lower:
                            is_script = True
                        break
        
        # 2. Format
        if is_json:
            try:
                parsed = json.loads(data)
                return json.dumps(parsed, indent=4)
            except:
                pass
        
        if is_script:
             # Force beautify even if heuristic fails
            return self._simple_js_beautify(data)
        
        # 3. Heuristic fallback (if no headers matched)
        stripped = data.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(data)
                return json.dumps(parsed, indent=4)
            except:
                pass
                
        return data

    def _simple_js_beautify(self, text):
        # Improved Indentation-based Beautifier
        res = []
        indent_level = 0
        indent_str = "    "
        i = 0
        length = len(text)
        
        while i < length:
            char = text[i]
            if char == '{':
                res.append("{\n")
                indent_level += 1
                res.append(indent_str * indent_level)
            elif char == '}':
                res.append("\n")
                indent_level = max(0, indent_level - 1)
                res.append(indent_str * indent_level)
                res.append("}")
            elif char == ';':
                res.append(";\n")
                res.append(indent_str * indent_level)
            else:
                res.append(char)
            i += 1
            
        return "".join(res)

class RegexListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def insertUpdate(self, e):
        self.callback(e)

    def removeUpdate(self, e):
        self.callback(e)

    def changedUpdate(self, e):
        self.callback(e)
