from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from javax.swing import JTextArea, JScrollPane, JMenuItem, JPanel, JLabel, JTextField, JSplitPane, SwingConstants, JTabbedPane, SwingUtilities, JComboBox
from javax.swing.event import DocumentListener
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
        # Left side: Response Data
        self._response_area = JTextArea()
        self._response_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._response_area.setLineWrap(True)
        self._response_scroll = JScrollPane(self._response_area)
        self._response_scroll.setPreferredSize(Dimension(500, 400))
        
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
        self._split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._response_scroll, self._regex_panel)
        self._split_pane.setResizeWeight(0.5)

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
        data = None
        response_bytes = message_info.getResponse()
        
        if response_bytes:
            try:
                # Force UTF-8 decoding for proper Chinese character display
                data = String(response_bytes, "UTF-8")
            except Exception:
                data = self._helpers.bytesToString(response_bytes)
        else:
            request_bytes = message_info.getRequest()
            if request_bytes:
                try:
                    data = String(request_bytes, "UTF-8")
                except Exception:
                    data = self._helpers.bytesToString(request_bytes)
        
        if data:
            self._response_area.setText(data)
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

class RegexListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def insertUpdate(self, e):
        self.callback(e)

    def removeUpdate(self, e):
        self.callback(e)

    def changedUpdate(self, e):
        self.callback(e)
