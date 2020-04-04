
import utility

class EndpointModel(object):
    """
    This endpoint represents a group of requests that are all sent to the same URL, or roughly the same URL. The idea is to aggregate all endpoints that refer on the backend to the same code path.
    """

    def __init__(self, method, url, fuzzed=False):
        """
        Main constructor method.

        Args:
            method: the HTTP method for this endpoint.
            url: the normalized url for this endpoint. See `EndpointTableModel.generateEndpointHash()`
            fuzzed: whether this endpoint has been fuzzed already
        """

        self.method = method
        self.url = url
        self.nb = 0
        self.requests = []
        self.fuzzed = fuzzed

    def add(self, requestModel):
        """
        Adds a request that corresponds to this endpoint as per our normalization strategies.

        Args:
            requestModel: a RequestModel object.
        """
        self.nb += 1
        self.requests.append(requestModel)

    @property
    def percentSameStatus(self):
        """
        Computates the number of requests that have the same status. This is done by iterating through the requests made to this endpoint and comparing the statusCode of the original response versus the new response.
        """
        nb = 0
        for request in self.requests:
            if request.repeatedAnalyzedResponse:
                if request.repeatedAnalyzedResponse.statusCode == request.analyzedResponse.statusCode:
                    nb += 1

        total_requests = len(self.requests)

        percentage = round((nb * 100) / total_requests)

        return percentage

    @property
    def percentSameLength(self):
        """
        Computates the number of requests that have the same length. This is done by iterating through the requests made to this endpoint and comparing the length of the original response versus the new response.
        """
        nb = 0
        for request in self.requests:
            if request.repeatedHttpRequestResponse:
                if len(request.repeatedHttpRequestResponse.response) == len(request.httpRequestResponse.response):
                    nb += 1

        total_requests = len(self.requests)
        percentage = round((nb * 100) / total_requests)

        return percentage

    @property
    def containsId(self):
        """
        Boolean computed function that is True if any of the requests associated with this endpoint contain an ID. An ID is defined as anything that matches the regex in `utility.regex`.
        """
        for request in self.requests:
            for regex in utility.regex:
                if regex.search(request.httpRequestResponse.request) != None:
                    return True

        return False

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
        self.repeatedAnalyzedResponse = None
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

    def wasReproducible(self):
        """
        Returns whether this requests could be reproduced last time it was resent.

        Reproducible in this context means that the request reached the endpoint and was successfully authenticated by the target server. We use this criteria to determine whether it is worth it to fuzz the endpoint or we are just going to be fuzzing the 401 page.

        Returns:
            boolean: true if the request is reproducible.
        """
        if not self.repeatedAnalyzedResponse:
            return False

        return self.analyzedResponse.statusCode == self.repeatedAnalyzedResponse.statusCode

class ReplacementRuleModel():
    def __init__(self, id, type, search, replacement):
        self.id = id
        self.type = type
        self.search = search
        self.replacement = replacement
