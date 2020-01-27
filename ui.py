from javax.swing import JTable;
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing import BoxLayout
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JComboBox
from javax.swing import JOptionPane
from javax.swing import Box
from javax.swing import BorderFactory
from java.awt import Color
from java.awt import Dimension
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import Component
from java.lang import String
from tables import Table
from implementations import MessageEditorController, HttpService
import jarray
import re
from utility import perform_request, apply_rules, get_header, log
from utility import REPLACE_HEADER_NAME, NoSuchHeaderException

class ToolboxUI():

    BUTTON_WIDTH = 140
    BUTTON_HEIGHT = 30
    CONFIG_PAGE_WIDTH = 2000

    def buildUi(self, state, callbacks):
        """
        Handles the building of the UI components using Swing, a UI library.
        """

        self.callbacks = ToolboxCallbacks(state, callbacks)

        tabs = JTabbedPane()
        resultsPane = self.buildResultsPane(state, callbacks)
        configPane = self.buildConfigPane(state, callbacks)

        tabs.addTab("Results", resultsPane)
        tabs.addTab("Config", configPane)


        return tabs

    def buildResultsPane(self, state, callbacks):
        """
        Builds the results pane in the confiuration page
        """
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        requestTable = self.buildRequestTable(state, callbacks)
        tabs = self.buildMessageViewer(state, callbacks)

        splitpane.setLeftComponent(requestTable)
        splitpane.setRightComponent(tabs)

        callbacks.customizeUiComponent(requestTable)
        callbacks.customizeUiComponent(tabs)

        return splitpane

    def buildConfigPane(self, state, callbacks):
        """
        Builds the config pane, section per section.
        """
        configPage = Box.createVerticalBox()
        configPage.setBorder(BorderFactory.createLineBorder(Color.black));

        configPage.add(self.buildScope(state, callbacks))
        configPage.add(self.buildReplacementRules(state, callbacks))
        configPage.add(self.buildSessionCheck(state, callbacks))

        return configPage

    def buildScope(self, state, callbacks):
        """
        Builds the scope pane in the configuration page
        """
        scope = JPanel()
        scope.setLayout(None)
        scope.setMaximumSize(Dimension(self.CONFIG_PAGE_WIDTH, 300))

        title = self.getTitle("Scope Selection", 20, 10)

        refresh = self.getButton("Refresh", 20, 50)
        refresh.addActionListener(self.callbacks.refreshButtonClicked)

        textarea = self.getTextArea()
        state.scopeTextArea = textarea.viewport.view
        state.scopeTextArea.setText(callbacks.loadExtensionSetting("scopes"))

        scope.add(title)
        scope.add(refresh)
        scope.add(textarea)

        return scope

    def buildReplacementRules(self, state, callbacks):
        """
        Builds the replacement rules section in the configuration page
        """
        rules = JPanel()
        rules.setLayout(None)
        rules.setMaximumSize(Dimension(self.CONFIG_PAGE_WIDTH, 300))

        title = self.getTitle("Replacement Rules", 20, 10)

        add = self.getButton("Add", 20, 50)
        add.addActionListener(self.callbacks.addButtonClicked)

        edit = self.getButton("Edit", 20, 90)
        edit.addActionListener(self.callbacks.editButtonClicked)
        delete = self.getButton("Delete", 20, 130)
        delete.addActionListener(self.callbacks.deleteButtonClicked)

        table = Table(state.replacementRuleTableModel)
        tableView = JScrollPane(table)
        tableView.setBounds(180, 50, 800, 240)

        rules.add(title)
        rules.add(add)
        rules.add(edit)
        rules.add(delete)
        rules.add(tableView)

        try:
            storedReplacementRules = callbacks.loadExtensionSetting("replacementRules")
            state.replacementRuleTableModel.importJsonRules(storedReplacementRules)
        except (ValueError, KeyError):
            log("Invalid replacement rules stored. Ignoring.")
            pass

        return rules

    def buildSessionCheck(self, state, callbacks):
        """
        Builds the session check portion of the config page
        """
        rules = JPanel()
        rules.setLayout(None)
        rules.setMaximumSize(Dimension(self.CONFIG_PAGE_WIDTH, 300))

        title = self.getTitle("Session Check", 20, 10)

        check = self.getButton("Check", 20, 50)
        check.addActionListener(self.callbacks.checkButtonClicked)
        state.checkButton = check

        run_all = self.getButton("Run ALL", 20, 90)
        run_new = self.getButton("Run NEW", 20, 130)

        textarea = self.getTextArea()
        state.sessionCheckTextarea = textarea.viewport.view
        state.sessionCheckTextarea.setText(callbacks.loadExtensionSetting("scopeCheckRequest"))

        rules.add(title)
        rules.add(check)
        rules.add(run_all)
        rules.add(run_new)
        rules.add(textarea)

        return rules

    def getButton(self, label, positionX, positionY):
        """
        Creates a JButton with a specific label and position
        """
        button = JButton(label)
        button.setBounds(positionX, positionY, self.BUTTON_WIDTH, self.BUTTON_HEIGHT)

        return button

    def getTextArea(self):
        """
        Creates a scrollable textarea
        """
        textarea = JTextArea()
        textarea.setBounds(180, 50, 800, 240)
        scrollPane = JScrollPane(textarea)
        scrollPane.setBounds(180, 50, 800, 240)

        return scrollPane

    def getTitle(self, content, positionX, positionY):
        """
        Creates a title for the configuration page.
        """
        title = JLabel("<html><h2>" + content + "</h2></html>")
        title.setBounds(positionX, positionY, 1000, 30)

        return title

    def buildRequestTable(self, state, callbacks):
        """
        Builds the request list on the results page on the right.
        """
        splitpane = JSplitPane()
        splitpane.setDividerLocation(1000)

        endpointTable = Table(state.endpointTableModel)
        endpointTable.getColumnModel().getColumn(0).setPreferredWidth(15)
        endpointTable.getColumnModel().getColumn(1).setPreferredWidth(500)
        endpointTable.setAutoCreateRowSorter(True)

        endpointView = JScrollPane(endpointTable)
        callbacks.customizeUiComponent(endpointTable)
        callbacks.customizeUiComponent(endpointView)

        requestTable = Table(state.requestTableModel)
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(500)

        requestView = JScrollPane(requestTable)
        callbacks.customizeUiComponent(requestTable)
        callbacks.customizeUiComponent(requestView)

        splitpane.setLeftComponent(endpointView)
        splitpane.setRightComponent(requestView)

        return splitpane

    def buildMessageViewer(self, state, callbacks):
        """
        Builds the panel that allows users to view requests on the results page.
        """
        tabs = JTabbedPane()
        messageEditor = MessageEditorController(state)
        state.requestViewer = callbacks.createMessageEditor(messageEditor, False)
        state.responseViewer = callbacks.createMessageEditor(messageEditor, False)
        tabs.addTab("Request", state.requestViewer.getComponent())
        tabs.addTab("Response", state.responseViewer.getComponent())

        return tabs

class InvalidInputException(Exception):
    pass

class ToolboxCallbacks(object):
    """
    Handles all callbacks for Swing objects.
    """
    def __init__(self, state, burpCallbacks):
        """
        Main constructor.

        Args:
            state: the state object.
            burpCallbacks: the burp callbacks object.
        """
        self.state = state
        self.burpCallbacks = burpCallbacks

    def refreshButtonClicked(self, event):
        """
        Handles click of refresh button. This reloads the results page with the new scope.
        """
        self.state.endpointTableModel.clear()

        scopes = self.state.scopeTextArea.text
        self.burpCallbacks.saveExtensionSetting("scopes", scopes)

        scope_urls = scopes.split("\n")
        for url in scope_urls:
            url = url.strip()
            if not url:
                continue

            requests = self.burpCallbacks.getSiteMap(url)
            for request in requests:
                self.state.endpointTableModel.add(request)

    def buildAddEditPrompt(self, typeValue=None, searchValue=None, replacementValue=None):
        """
        Builds the replacement rules add/edit prompt.
        """
        panel = Box.createVerticalBox()

        typeLabel = JLabel("Replacement type")
        type = JComboBox([REPLACE_HEADER_NAME])
        searchLabel = JLabel("Header Name / Search String")
        search = JTextField()
        replaceLabel = JLabel("Replacement Value")
        replacement = JTextField()

        panel.add(typeLabel)
        panel.add(type)
        panel.add(searchLabel)
        panel.add(search)
        panel.add(replaceLabel)
        panel.add(replacement)

        if typeValue:
            type.setSelectedItem(typeValue)

        if searchValue:
            search.text = searchValue

        if replacementValue:
            replacement.text = replacementValue

        title = "Add Replacement Rule" if type == None else "Edit Replacement Rule"

        result = JOptionPane.showConfirmDialog(None, panel, "Add Replacement Rule", JOptionPane.PLAIN_MESSAGE)

        if result == JOptionPane.OK_OPTION:
            if search.text == "":
                JOptionPane.showMessageDialog(None, "Invalid header name / search string")
                raise InvalidInputException()
            else:
                return type.selectedItem, search.text, replacement.text
        else:
            raise InvalidInputException()

    def addButtonClicked(self, event):
        """
        Handles click of the replacement rule add button.
        """
        try:
            type, search, replacement = self.buildAddEditPrompt()
        except InvalidInputException:
            return

        self.state.replacementRuleTableModel.add(type, search, replacement)
        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def editButtonClicked(self, event):
        """
        Handles click of the edit button.
        """
        rule = self.state.replacementRuleTableModel.selected

        try:
            type, search, replacement = self.buildAddEditPrompt(rule.type, rule.search, rule.replacement)
        except InvalidInputException:
            return

        self.state.replacementRuleTableModel.edit(rule.id, type, search, replacement)
        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def deleteButtonClicked(self, event):
        """
        Handles click of the delete button.
        """
        rule = self.state.replacementRuleTableModel.selected
        self.state.replacementRuleTableModel.delete(rule.id)

        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def checkButtonClicked(self, event):
        """
        Gets called when a user clicks the check button. Repeats the request with the modifications made and assesses whether the result is positive or negative.

        Normalizes the newlines in the textarea to make them compatible with burp APIs and then converts them into a binary string.
        """
        baseRequestString = re.sub(r"(?!\r)\n", "\r\n", self.state.sessionCheckTextarea.text)
        baseRequest = self.burpCallbacks.helpers.stringToBytes(baseRequestString)
        self.burpCallbacks.saveExtensionSetting("scopeCheckRequest", baseRequestString)

        try:
            hostHeader = get_header(self.burpCallbacks, baseRequest, "host")
        except NoSuchHeaderException:
            log("Check request failed: no Host header present in session check request.")
            self.checkButtonSetFail()
            return

        target = HttpService(hostHeader, 443, "https")

        modifiedRequest = apply_rules(self.burpCallbacks(), self.state.replacementRuleTableModel.rules, baseRequest)
        response = perform_request(self.burpCallbacks, target, modifiedRequest)
        analyzedResponse = self.burpCallbacks.helpers.analyzeResponse(response.response)

        if analyzedResponse.statusCode == 200:
            self.state.checkButton.setBackground(Color(107,255,127))
            self.state.checkButton.setText("Check: OK")
        else:
            log("Check request failed: response not 200 OK.")
            self.checkButtonSetFail()

    def checkButtonSetFail(self):
        """
        Convenience function to make the check button red.
        """
        self.state.checkButton.setBackground(Color(255,202,128))
        self.state.checkButton.setText("Check: FAIL")
