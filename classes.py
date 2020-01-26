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
from collections import OrderedDict

class Table(JTable):
    """
    Generic table for all tables in our UI.
    """
    def __init__(self, model):
        """
        Constructor function.

        Args:
            model: an object that implements AbstractTableModel, such as RequestTableModel.
        """
        self.model = model

    def changeSelection(self, row, col, toggle, extend):
        """
        Called by Swing when a hacker clicks on a row. Calls selectRow on our TableModel and then calls the parent function to handle highlighting of the clicked cell and etc.

        Args:
            row: row number
            col: col number
            toggle: whether to toggle the selection upon this click.
            extend: whether to extend the selection and have two or more rows selected.
        """
        self.model.selectRow(row)
        JTable.changeSelection(self, row, col, toggle, extend)

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

class EndpointModel(object):
    def __init__(self, method, url):
        self.method = method
        self.url = url
        self.nb = 0
        self.nb_same_status = 0
        self.nb_same_len = 0
        self.requests = []

    def add(self, requestModel):
        self.nb += 1
        self.requests.append(requestModel)

class RequestModel(object):
    """
    Model that represents requests on the right panel on the results page.
    """
    def __init__(self, httpRequestResponse, analyzedRequest):
        """
        Main constructor.

        Args:
            httpRequestResponse: a httpRequestResponse as returned by burp apis.
            analyzedRequest: an object as returned by analyzeRequest(httpRequestResponse).
        """
        self.httpRequestResponse = httpRequestResponse
        self.analyzedRequest = analyzedRequest

        self.repeatedHttpRequestResponse = None
        self.repeatedAnalyzedRequest = None

        self.repeated = False

class EndpointTableModel(AbstractTableModel):

    cols = ["Method", "URL", "#", "Same Status", "Same Len"]

    def __init__(self, state, callbacks):
        self._lock = Lock()
        self.state = state
        self.callbacks = callbacks
        self.endpoints = OrderedDict()

    def add(self, httpRequestResponse):
        """
        Adds a http request to the internal state and fires the trigger for a reload of the table.

        This is called both by a click on the "refresh" button, which fetches requests from previous requests and by processHttpMessage which fetches requests as they occur.

        Args:
        httpRequestResponse: an HttpRequestResponse java object as returned by burp.
        """
        self._lock.acquire()

        analyzedRequest = self.callbacks.helpers.analyzeRequest(httpRequestResponse)

        hash, url, method = self.generateEndpointHash(analyzedRequest)
        if hash not in self.endpoints:
            self.endpoints[hash] = EndpointModel(method, url)

        self.endpoints[hash].add(RequestModel(httpRequestResponse, analyzedRequest))

        added_at_index = len(self.endpoints)
        self.fireTableRowsInserted(added_at_index, added_at_index)

        self._lock.release()

    def generateEndpointHash(self, analyzedRequest):
        """
        In this endpoint, a hash is a string that is used to group requests.

        Requests that have the same URL and method should be grouped together to avoid duplication of testing effort.

        Args:
            analyzedRequest: an analyzed request as returned by helpers.analyzeRequest()
        """
        url = analyzedRequest.url.toString().split("?")[0]
        method = analyzedRequest.method

        return method + "|" + url, url, method

    def getRowCount(self):
        """
        Returns the number of rows so that swing can create the table.
        """
        try:
            return len(self.endpoints)
        except:
            return 0

    def getColumnCount(self):
        """
        Returns the number of columns so that Swing can create the table.
        """
        return len(self.cols)

    def getColumnName(self, columnIndex):
        """
        Returns the column name at an individual index so that Swing can create the table.

        Args:
            columnIndex: the column index to get the column name for.
        """
        return self.cols[columnIndex]

    def getEndpoint(self, rowIndex):
        """
        Gets EndpointModel at specific row.

        Because our endpoints item is not a list, we are required to do some extra function calls.

        Args:
            rowIndex: specific row to fetch the EndpointModel for.
        """
        return self.endpoints.items()[rowIndex][1]

    def selectRow(self, rowIndex):
        """
        Gets called when a hacker clicks on a row.

        In the case of this particular model, a click triggers an event on the RequestsTableModel that causes it to display the requests that have been sent to this endpoint.

        Args:
            rowIndex: the row that was clicked.
        """
        endpoint = self.getEndpoint(rowIndex)
        self.state.requestsTableModel.updateRequests(endpoint.requests)

    def getValueAt(self, rowIndex, columnIndex):
        """
        Gets the value for each individual cell.

        Args:
            rowIndex: the y value to fetch the value for.
            columnIndex: the y value to fetch the value for.
        """
        endpointModel = self.getEndpoint(rowIndex)
        if columnIndex == 0:
            return endpointModel.method
        elif columnIndex == 1:
            return endpointModel.url
        elif columnIndex == 2:
            return len(endpointModel.requests)
        elif columnIndex == 3:
            return endpointModel.nb_same_status
        elif columnIndex == 4:
            return endpointModel.nb_same_len

class RequestTableModel(AbstractTableModel):
    """
    Table model for the requests panel on the Results tab on the right.
    """

    cols = ["URL", "Orig Status", "Status", "Orig Len", "Resp Len", "Diff"]

    def __init__(self, state, callbacks):
        """
        Initialization function.

        Args:
            state: the general state object.
            callbacks: burp callbacks
        """
        self.requests = []
        self._lock = Lock()
        self.state = state
        self.callbacks = callbacks

    def getRowCount(self):
        """
        Returns the number of elements in this table.
        """
        try:
            return len(self.requests)
        except:
            return 0

    def getColumnCount(self):
        """
        Returns the number of columns in this table.
        """
        return len(self.cols)

    def getColumnName(self, columnIndex):
        """
        Gets the name for the column at this particular position.

        Args:
            columnIndex: the index to fetch the column name for.
        """
        return self.cols[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        """
        Returns the corresponding value for the request at the position specified by the parameters.

        Args:
            rowIndex: y value to return the value for.
            columnIndex: x value to return the value for.
        """
        request = self.requests[rowIndex]
        if columnIndex == 0:
            return request.analyzedRequest.url.getPath()
        elif columnIndex == 1:
            return request.analyzedRequest.status
        elif columnIndex == 2:
            if request.repeatedAnalyzedRequest != None:
                return request.repeatedAnalyzedRequest.status
            else:
                return ""
        elif columnIndex == 3:
            return request.httpRequestResponse.response.length
        elif columnIndex == 4:
            if request.repeatedAnalyzedRequest != None:
                return request.repeaterhttpRequestResponse.response.length
            else:
                return ""
        elif columnIndex == 5:
            return ""



    def updateRequests(self, requests):
        """
        Replaces the requests we are currently displaying with a new set of requests.

        Gets fired when a user clicks on the endpoint table.

        Args:
            requests: an array of requests to replace the current requests with.
        """
        self._lock.acquire()

        nb_requests = len(requests)
        self.requests = requests
        self.fireTableRowsInserted(0, nb_requests - 1)

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
        """
        Handles click of refresh button. This reloads the results page with the new scope.
        """
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
