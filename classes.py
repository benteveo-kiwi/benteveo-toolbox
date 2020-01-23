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

class EndpointTableModel(AbstractTableModel):

    cols = ["Method", "URL", "#", "Same Status", "Same Len"]

    def __init__(self, state):
        self._lock = Lock()
        self.state = state

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
        if messageIsRequest:
            return

        logEntry = LogEntry(toolFlag, self.state._callbacks.saveBuffersToTempFiles(messageInfo), self.state._helpers.analyzeRequest(messageInfo).getUrl())
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
    def buildUi(self, state, callbacks):
        """
        Handles the building of the UI components using Swing, a UI library.
        """

        tabs = JTabbedPane()
        resultsPane = self.buildResultsPane(state, callbacks)

        tabs.addTab("Results", resultsPane)

        return tabs

    def buildResultsPane(self, state, callbacks):
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        requestTable = self.buildRequestTable(state, callbacks)
        tabs = self.buildMessageViewer(state, callbacks)

        splitpane.setLeftComponent(requestTable)
        splitpane.setRightComponent(tabs)

        callbacks.customizeUiComponent(requestTable)
        callbacks.customizeUiComponent(tabs)

        return splitpane

    def buildRequestTable(self, state, callbacks):
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
        tabs = JTabbedPane()
        messageEditor = MessageEditorController(state)
        state._requestViewer = callbacks.createMessageEditor(messageEditor, False)
        state._responseViewer = callbacks.createMessageEditor(messageEditor, False)
        tabs.addTab("Request", state._requestViewer.getComponent())
        tabs.addTab("Response", state._responseViewer.getComponent())

        return tabs
