from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IHttpService
from burp import IExtensionStateListener
from utility import log

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
        """
        Main constructor method.

        Args:
            state: the state object.
            callbacks: the burp callbacks object.
        """
        self.state = state
        self.callbacks = callbacks

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        New HTTP message is being sent by burp.

        Args:
            toolFlag: a number which represents the tool that generated the traffic.
            messageIsRequest: true if message is request, false if isResponse
            messageInfo: a httpRequestResponse object which contains all the relevant information.
        """

class MessageEditorController(IMessageEditorController):
    """
    This class is in charge of displaying message editors, used to view request details on the results panel.
    """
    def __init__(self, state):
        """
        Main constructor.

        Args:
            state: the state object.
        """
        self.state = state

    def getHttpService(self):
        """
        Getter for the httpService object.
        """
        return self.state.currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        """
        Getter for the request object.
        """
        return self.state.currentlyDisplayedItem.getRequest()

    def getResponse(self):
        """
        Getter for the response object.
        """
        return self.state.currentlyDisplayedItem.getResponse()

class HttpService(IHttpService):
    """
    Represents an endpoint which we can send HTTP requests to.
    """
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

class ExtensionStateListener(IExtensionStateListener):
    """
    Listens for changes to extension state.
    """

    def __init__(self, state):
        """
        Main constructor.

        Args:
            state: the state object.
        """
        self.state = state

    def extensionUnloaded(self):
        """
        This function gets called when the extension is unloaded and is in charge of cleanup.
        """
        self.state.executorService.shutdown()
        log("Successfully shut down.")
