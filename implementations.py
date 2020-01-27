from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IHttpService

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
    def __init__(self, state, callbacks):
        self.state = state
        self.callbacks = callbacks

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        New HTTP message is being sent by burp.
        """
        if messageIsRequest:

            print type(messageInfo.request), messageInfo.request
            # print self.callbacks.helpers.analyzeRequest(messageInfo.request).headers, len(self.callbacks.helpers.analyzeRequest(messageInfo.request).headers)
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


class HttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol
