from burp import ITab
from burp import IHttpListener
from java.util import ArrayList
from threading import Lock
from burp import IMessageEditorController
from javax.swing import JTable;
from javax.swing.table import AbstractTableModel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing import BoxLayout
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import Box
from javax.swing import BorderFactory
from java.awt import Color
from java.awt import Dimension
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import Component

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):

        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender.state._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender.state._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender.state._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)

class EndpointModel(object):
    def __init__(self, method, url):
        self.method = method
        self.url = url
        self.nb = 0
        self.nb_same_status = 0
        self.nb_same_len = 0
        self.requests = []

class ReplacementRulesTableModel(AbstractTableModel):

    cols = ["Rule type", "Detail"]

    def __init__(self, state):
        self._lock = Lock()
        self.state = state
        self.active_rules = {}

    def getRowCount(self):
        try:
            return len(self.active_rules)
        except:
            return 0

    def getColumnCount(self):
        return len(self.cols)

    def getColumnName(self, columnIndex):
        return self.cols[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        return
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self.state._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""


class EndpointTableModel(AbstractTableModel):

    cols = ["Method", "URL", "#", "Same Status", "Same Len"]

    def __init__(self, state):
        self._lock = Lock()
        self.state = state
        self.endpoints = {}

    def generateEndpointHash(self, httpRequestResponse):
        """
        In this endpoint, a hash is a string that is used to group requests.

        Requests that have the same URL and method should be grouped together to avoid duplication of testing effort.

        Args:
            httpRequestResponse: an HttpRequestResponse java object as returned by burp.
        """

        request = self.state.helpers.analyzeRequest(httpRequestResponse)

        method = request.method
        url = request.url

        return method + "|" + url

    def getRowCount(self):
        try:
            return len(self.endpoints)
        except:
            return 0

    def getColumnCount(self):
        return len(self.cols)

    def getColumnName(self, columnIndex):
        return self.cols[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        return
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self.state._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    # def addLogEntry(self, logEntry):
    #     return
    #     self._lock.acquire()
    #     row = self._log.size()
    #     self._log.add(logEntry)
    #     self.fireTableRowsInserted(row, row)
    #     self._lock.release()

class RequestTableModel(AbstractTableModel):

    cols = ["Orig Status", "Status", "Orig Len", "Resp Len", "Diff"]

    def __init__(self, state):
        self._log = ArrayList()
        self._lock = Lock()
        self.state = state

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return len(self.cols)

    def getColumnName(self, columnIndex):
        return self.cols[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self.state._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    def addLogEntry(self, logEntry):
        self._lock.acquire()
        row = self._log.size()
        self._log.add(logEntry)
        self.fireTableRowsInserted(row, row)
        self._lock.release()

class Tab(ITab):
    def __init__(self, splitpane):
        self.splitpane = splitpane

    def getTabCaption(self):
        """
        Adds a tab to burp.
        """
        return "Toolbox"

    def getUiComponent(self):
        """
        Tells burp which UI element to display on our custom tab.
        """
        return self.splitpane

class HttpListener(IHttpListener):
    def __init__(self, state):
        self.state = state

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        New HTTP message is being sent by burp.
        """
        # if messageIsRequest:
        #     return
        #
        # logEntry = LogEntry(toolFlag, self.state._callbacks.saveBuffersToTempFiles(messageInfo), self.state._helpers.analyzeRequest(messageInfo).getUrl())
        #self.state.endpointTableModel.addLogEntry(logEntry)

class MessageEditorController(IMessageEditorController):

    def __init__(self, state):
        self.state = state

    def getHttpService(self):
        return self.state._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self.state._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self.state._currentlyDisplayedItem.getResponse()

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
        endpointView = JScrollPane(endpointTable)
        callbacks.customizeUiComponent(endpointTable)
        callbacks.customizeUiComponent(endpointView)

        requestTable = Table(state.requestTableModel)
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
        state._requestViewer = callbacks.createMessageEditor(messageEditor, False)
        state._responseViewer = callbacks.createMessageEditor(messageEditor, False)
        tabs.addTab("Request", state._requestViewer.getComponent())
        tabs.addTab("Response", state._responseViewer.getComponent())

        return tabs

class ToolboxCallbacks(object):
    """
    Handles all callbacks for Swing objects.
    """
    def __init__(self, state, burpCallbacks):
        self.state = state
        self.burpCallbacks = burpCallbacks

    def refreshButtonClicked(self, event):
        scopes = self.state.scopeTextArea.getText()
        self.burpCallbacks.saveExtensionSetting("scopes", scopes)
