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
import re

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
        self.model.selectRow(self.convertRowIndexToModel(row))
        JTable.changeSelection(self, row, col, toggle, extend)

class ReplacementRulesTableModel(AbstractTableModel):

    cols = ["Rule type", "Detail"]

    def __init__(self, state):
        self.lock = Lock()
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

class EndpointTableModel(AbstractTableModel):
    """
    Handles interactions between raw data and the Swing table.

    Also keeps in the endpoints attribute a list of all known endpoints.
    """

    cols = ["Method", "URL", "#", "Same Status", "Same Len"]
    regex = [
        re.compile("[a-f0-9]{64}"), # 748bbea58bb5db34e95d02edb2935c0f25cb1593e5ab837767e260a349c02ca7
    ]

    def __init__(self, state, callbacks):
        """
        Main constructor.

        Args:
            state: the global state object.
            callbacks: the burp callbacks object.
        """
        self.lock = Lock()
        self.state = state
        self.callbacks = callbacks
        self.endpoints = OrderedDict()

    def generateEndpointHash(self, analyzedRequest):
        """
        In this endpoint, a hash is a string that is used to group requests.

        Requests that have the same URL and method should be grouped together to avoid duplication of testing effort. For example, "/users/1" and "/users/2" should both generate the same hash.

        We do this by having a collection of regular expressions that are ran against each folder in every URL. If the regex matches, the folder is replaced in such a way that it becomes "/users/{ID}", which results in equal hashes for these kind of endpoints.

        Args:
            analyzedRequest: an analyzed request as returned by helpers.analyzeRequest()
        """
        url = analyzedRequest.url.toString().split("?")[0]
        method = analyzedRequest.method

        hash_url = []
        for folder in url.split("/"):
            if self.isId(folder):
                hash_url.append("{ID}")
            else:
                hash_url.append(folder)

        url = "/".join(hash_url)

        return method + "|" + url, url, method

    def isId(self, folder):
        """
        Checks if this "folder" of the URL path looks like an ID according to our predefined regular expressions.

        Args:
            folder: a part of the file path. E.g. if you have a URL that looks like "images/image.jpg" then this function will be invoked twice, once with "images" and another with "image.jpg".
        """
        for regex in self.regex:
            if regex.match(folder):
                return True

        return False

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

    def add(self, httpRequestResponse):
        """
        Adds a http request to the internal state and fires the trigger for a reload of the table.

        This is called by a click on the "refresh" button, which fetches requests from previous requests. We ignore requests without responses and OPTIONS requests as these don't tend to have IDOR.

        Args:
        httpRequestResponse: an HttpRequestResponse java object as returned by burp.
        """

        with self.lock:

            analyzedRequest = self.callbacks.helpers.analyzeRequest(httpRequestResponse)

            hash, url, method = self.generateEndpointHash(analyzedRequest)

            if not httpRequestResponse.response:
                return

            if method == "OPTIONS":
                return

            if hash not in self.endpoints:
                self.endpoints[hash] = EndpointModel(method, url)

            self.endpoints[hash].add(RequestModel(httpRequestResponse, self.callbacks))

            added_at_index = len(self.endpoints)
            self.fireTableRowsInserted(added_at_index - 1, added_at_index - 1)

    def clear(self):
        """
        Gets called when the user clicks the Refresh button in order to clear the state.

        Deletes all currently stored endpoints.
        """

        with self.lock:
            length = len(self.endpoints)
            if length == 0:
                return
                
            self.endpoints = OrderedDict()
            self.fireTableRowsDeleted(0, length - 1)

    def selectRow(self, rowIndex):
        """
        Gets called when a hacker clicks on a row.

        In the case of this particular model, a click triggers an event on the RequestsTableModel that causes it to display the requests that have been sent to this endpoint.

        Args:
            rowIndex: the row that was clicked.
        """
        endpoint = self.getEndpoint(rowIndex)
        self.state.requestTableModel.updateRequests(endpoint.requests)
        self.state.requestTableModel.selectRow(0)

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

class RequestModel(object):
    """
    Model that represents requests on the right panel on the results page.
    """
    def __init__(self, httpRequestResponse, callbacks):
        """
        Main constructor.

        See https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#analyzeRequest(burp.IHttpRequestResponse) for more info. Analysis of the response is performed as-needed because it is very slow and hangs burp.

        Args:
        httpRequestResponse: a httpRequestResponse as returned by burp apis.
        callbacks: burp callbacks object.
        """
        self.httpRequestResponse = httpRequestResponse
        self.callbacks = callbacks

        self._analyzedRequest = None
        self._analyzedResponse = None

        self.repeatedHttpRequestResponse = None
        self.repeatedAnalyzedRequest = None

        self.repeated = False

    @property
    def analyzedRequest(self):
        """
        This is a property method that is invoked when the analyzedRequest property is accessed.
        """
        if self._analyzedRequest:
            return self._analyzedRequest
        else:
            self._analyzedRequest = self.callbacks.helpers.analyzeRequest(self.httpRequestResponse)
            return self._analyzedRequest

    @property
    def analyzedResponse(self):
        """
        This is a property method that is invoked when the analyzedResponse property is accessed.
        """
        if self._analyzedResponse:
            return self._analyzedResponse
        else:
            if self.httpRequestResponse.response:
                self._analyzedResponse = self.callbacks.helpers.analyzeResponse(self.httpRequestResponse.response)
                return self._analyzedResponse
            else:
                return None


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
        self.lock = Lock()
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
            url = request.analyzedRequest.url
            queryString = url.query
            if queryString:
                return url.path + "?" + queryString
            else:
                return url.path
        elif columnIndex == 1:
            if request.analyzedResponse:
                return request.analyzedResponse.statusCode
            else:
                return ""
        elif columnIndex == 2:
            if request.repeatedAnalyzedRequest:
                return request.repeatedAnalyzedRequest.status
            else:
                return ""
        elif columnIndex == 3:
            if request.httpRequestResponse.response:
                return len(request.httpRequestResponse.response)
            else:
                return ""
        elif columnIndex == 4:
            if request.repeatedAnalyzedRequest:
                return len(request.repeaterhttpRequestResponse.response)
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
        with self.lock:
            nb_requests = len(requests)
            self.requests = requests
            self.fireTableRowsInserted(0, nb_requests - 1)

    def selectRow(self, rowIndex):
        """
        Gets called when a hacker clicks on a request in the rightmost panel.

        Args:
            rowIndex: the row number that was clicked.
        """
        request = self.requests[rowIndex]

        self.state.requestViewer.setMessage(request.httpRequestResponse.request, False)
        self.state.responseViewer.setMessage(request.httpRequestResponse.response, False)
        self.state.currentlyDisplayedItem = request.httpRequestResponse



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
        return self.state.currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self.state.currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self.state.currentlyDisplayedItem.getResponse()

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
        print "Add! :D"
