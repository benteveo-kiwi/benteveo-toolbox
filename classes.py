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

class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url

class TableModel(AbstractTableModel):
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
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

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
        self.state.tableModel.addLogEntry(logEntry)

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
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        logTable = Table(state.tableModel)
        scrollPane = JScrollPane(logTable)

        tabs = JTabbedPane()
        messageEditor = MessageEditorController(state)
        state._requestViewer = callbacks.createMessageEditor(messageEditor, False)
        state._responseViewer = callbacks.createMessageEditor(messageEditor, False)
        tabs.addTab("Request", state._requestViewer.getComponent())
        tabs.addTab("Response", state._responseViewer.getComponent())

        splitpane.setLeftComponent(scrollPane)
        splitpane.setRightComponent(tabs)

        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        return splitpane
