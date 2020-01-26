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
        This is a property method that is invoked when the analyzedRequest property is accessed. We do it this way because it prevents us having to analyze all requests at the same time.
        """
        if self._analyzedRequest:
            return self._analyzedRequest
        else:
            self._analyzedRequest = self.callbacks.helpers.analyzeRequest(self.httpRequestResponse)
            return self._analyzedRequest

    @property
    def analyzedResponse(self):
        """
        This is a property method that is invoked when the analyzedResponse property is accessed. We do it this way because it prevents us having to analyze all responses at the same time.
        """
        if self._analyzedResponse:
            return self._analyzedResponse
        else:
            if self.httpRequestResponse.response:
                self._analyzedResponse = self.callbacks.helpers.analyzeResponse(self.httpRequestResponse.response)
                return self._analyzedResponse
            else:
                return None

class ReplacementRuleModel():
    def __init__(self, id, type, search, replacement):
        self.id = id
        self.type = type
        self.search = search
        self.replacement = replacement
