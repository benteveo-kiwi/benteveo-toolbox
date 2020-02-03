from burp import IExtensionStateListener
from burp import IHttpListener
from burp import IHttpService
from burp import IMessageEditorController
from burp import IScannerInsertionPoint
from burp import ITab
from java.io import ByteArrayOutputStream
from java.lang import IllegalArgumentException
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
    This class is in charge of returning information regarding the currently displayed request for sending to other tools.
    """
    def __init__(self, state, kind):
        """
        Main constructor.

        Args:
            state: the state object.
            kind: "original" or "repeated"
        """
        self.state = state
        self.kind = kind

    def getHttpService(self):
        """
        Getter for the httpService object.
        """
        if self.kind == "original":
            return self.state.originalHttpRequestResponse.getHttpService()
        else:
            if self.state.repeatedHttpRequestResponse:
                return self.state.repeatedHttpRequestResponse.getHttpService()

    def getRequest(self):
        """
        Getter for the request object.
        """
        if self.kind == "original":
            return self.state.originalHttpRequestResponse.getRequest()
        else:
            if self.state.repeatedHttpRequestResponse:
                return self.state.repeatedHttpRequestResponse.getRequest()

    def getResponse(self):
        """
        Getter for the response object.
        """
        if self.kind == "original":
            return self.state.originalHttpRequestResponse.getResponse()
        else:
            if self.state.repeatedHttpRequestResponse:
                return self.state.repeatedHttpRequestResponse.getResponse()

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
        self.state.perRequestExecutorService.shutdown()
        self.state.shutdown = True
        log("Successfully shut down.")


class ScannerInsertionPoint(IScannerInsertionPoint):
    """
    Custom implementation of ScannerInsertionPoint.

    Allows us to specify the type of an attribute, unlike makeScannerInsertionPoint which forces the type to be "extension provided". Types are very important to ensure the proper encoding is put in place.
    """
    def __init__(self, callbacks, request, name, value, type, start, end):
        """
        Main constructor.

        Args:
            callbacks: the burp callbacks object.
            request: the request that this ScannerInsertionPoint corresponds to as byte[].
            name: the name of this parameter.
            value: the base value of this parameter
            type: the type of this IScannerInsertionPoint, see https://portswigger.net/burp/extender/api/burp/IScannerInsertionPoint.html
            start: start offset of the value of this parameter.
            end: the end offset of the value of this parameter.
        """
        self.callbacks = callbacks
        self.request = request
        self.name = name
        self.value = value
        self.type = type
        self.start = start
        self.end = end

    def getInsertionPointName(self):
        """
        Getter for the insertion point name.
        """
        return self.name

    def getBaseValue(self):
        """
        Getter for the base value.
        """
        return self.value

    def buildRequest(self, payload):
        """
        This is the main method through which an extension interacts with a IScannerInsertionPoint instance. They provide the payload through the payload parameter and we replace it in our request.

        If the parameter type is something that could be handled by Burp's helpers we update it in that way, otherwise we do it by modifying the byte arrays directly.

        Args:
            payload: the active scanner payload provided by the extension.
        """
        try:
            newParam = self.callbacks.helpers.buildParameter(self.name, self.callbacks.helpers.bytesToString(payload), self.type)
            return self.callbacks.helpers.updateParameter(self.request, newParam)
        except IllegalArgumentException:
            stream = ByteArrayOutputStream()
            stream.write(self.request[0:self.start])
            stream.write(payload)
            stream.write(self.request[self.end:])

            return stream.toByteArray()

    def getPayloadOffsets(self, payload):
        return [self.start, self.start + len(payload)]

    def getInsertionPointType(self):
        return self.type
