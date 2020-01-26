from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController

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
