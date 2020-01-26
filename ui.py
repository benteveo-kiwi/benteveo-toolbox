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
from tables import Table
from implementations import MessageEditorController
import jarray

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
        delete = self.getButton("Delete", 20, 130)

        table = Table(state.replacementRulesTableModel)
        tableView = JScrollPane(table)
        tableView.setBounds(180, 50, 800, 240)

        rules.add(title)
        rules.add(add)
        rules.add(edit)
        rules.add(delete)
        rules.add(tableView)

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
        run_all = self.getButton("Run ALL", 20, 90)
        run_new = self.getButton("Run NEW", 20, 130)
        textarea = self.getTextArea()

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

class ToolboxCallbacks(object):
    """
    Handles all callbacks for Swing objects.
    """
    def __init__(self, state, burpCallbacks):
        self.state = state
        self.burpCallbacks = burpCallbacks

    def refreshButtonClicked(self, event):
        """
        Handles click of refresh button. This reloads the results page with the new scope.
        """

        self.state.endpointTableModel.clear()

        scopes = self.state.scopeTextArea.getText()
        self.burpCallbacks.saveExtensionSetting("scopes", scopes)

        scope_urls = scopes.split("\n")
        for url in scope_urls:
            url = url.strip()
            if not url:
                continue

            requests = self.burpCallbacks.getSiteMap(url)
            for request in requests:
                self.state.endpointTableModel.add(request)

    def addButtonClicked(self, event):
        """
        Handles click of the replacement rule add button.
        """
        panel = Box.createVerticalBox()

        typeLabel = JLabel("Replacement type")
        type = JComboBox(["Replace by Header Name", "Replace String"])
        searchLabel = JLabel("Header Name / Search String")
        search = JTextField()
        replaceLabel = JLabel("Replacement Value")
        replace = JTextField()

        panel.add(typeLabel)
        panel.add(type)
        panel.add(searchLabel)
        panel.add(search)
        panel.add(replaceLabel)
        panel.add(replace)

        result = JOptionPane.showConfirmDialog(None, panel, "Add Replacement Rule", JOptionPane.PLAIN_MESSAGE)
