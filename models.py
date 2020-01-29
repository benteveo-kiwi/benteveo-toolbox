
class EndpointModel(object):
    """
    This endpoint represents a group of requests that are all sent to the same URL, or roughly the same URL. The idea is to aggregate all endpoints that refer on the backend to the same code path.
    """

    def __init__(self, method, url):
        """
        Main constructor method.

        Args:
            method: the HTTP method for this endpoint.
            url: the normalized url for this endpoint. See `EndpointTableModel.generateEndpointHash()`
        """

        self.method = method
        self.url = url
        self.nb = 0
        self.requests = []

    def add(self, requestModel):
        """
        Adds a request that corresponds to this endpoint as per our normalization strategies.

        Args:
            requestModel: a RequestModel object.
        """
        self.nb += 1
        self.requests.append(requestModel)

    @property
    def nb_same_status(self):
        """
        Computates the number of requests that have the same status. This is done by iterating through the requests made to this endpoint and comparing the statusCode of the original response versus the new response.
        """
        return 0

    @property
    def nb_same_len(self):
        """
        Computates the number of requests that have the same length. This is done by iterating through the requests made to this endpoint and comparing the length of the original response versus the new response.
        """
        return 0

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
        self.callbacks = callbacks

        self.httpRequestResponse = httpRequestResponse
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
