from burp import IScannerInsertionPoint, IParameter
from implementations import ScannerInsertionPoint, ContextMenuInvocation
from java.util.concurrent import Executors, ExecutionException
from tables import NoResponseException
from threading import Lock
from utility import log, ShutdownException, resend_request_model, PythonFunctionRunnable, sendMessageToSlack, resend_session_check
import java.lang.Exception
import java.lang.NullPointerException
import time
import utility
import logging

class SessionCheckNotReproducibleException(Exception):
    pass

class FuzzRunner(object):
    """
    Main fuzz runner class. In charge of interacting with the extensions
    """

    def __init__(self, state, callbacks, extensions):
        self.state = state
        self.callbacks = callbacks
        self.extensions = extensions

        self.lock = Lock()

    def run(self):
        """
        Main run method. Blocks the calling thread until threads are finished running.
        """
        return self.fuzzEndpoints()

    @utility.LogDecorator()
    def fuzzEndpoints(self):
        """
        Fuzzes endpoints as present in the state based on the user preferences.

        We attempt to fuzz only one request per endpoint, using our own criteria to differentiate between endpoints as defined in `EndpontTableModel.generateEndpointHash`. For each endpoint, we iterate through requests until we can find a single request whose status code is the same between both the original and the repeated request, we only fuzz once. Requests are ordered based on the number of parameters they have, giving preference to those with the higher number of parameters in order to attempt to maximise attack surface.

        Returns:
            tuple: (int, int) number of items scanned and number of items for which the scan could not be completed due to an exception.
        """

        endpoints = self.state.endpointTableModel.endpoints

        futures = []
        endpointsNotReproducibleCount = 0
        nbFuzzedTotal = 0
        nbExceptions = 0
        for key in endpoints:
            endpoint = endpoints[key]
            nbExceptions += self.checkMaxConcurrentRequests(futures, 10) # Only work on some futures at a time. This prevents a memory leak.

            if endpoint.fuzzed:
                continue

            sortedRequests = sorted(endpoint.requests, key=lambda x: len(x.analyzedRequest.parameters), reverse=True)

            fuzzed = False
            for request in sortedRequests:
                utility.sleep(self.state, 0.2)
                try:
                    resend_request_model(self.state, self.callbacks, request)
                except NoResponseException:
                    continue

                if request.wasReproducible():
                    endpointsNotReproducibleCount = 0
                    nbFuzzedTotal += 1

                    frm_futures = self.fuzzRequestModel(request)
                    futures.append((endpoint, request, frm_futures))

                    fuzzed = True
                    break

            if not fuzzed:
                endpointsNotReproducibleCount += 1
                log("Did not fuzz '%s' because no reproducible requests are possible with the current replacement rules" % endpoint.url)

        nbExceptions += self.checkMaxConcurrentRequests(futures, 0) # ensure all requests are done.

        return nbFuzzedTotal, nbExceptions

    @utility.LogDecorator()
    def checkMaxConcurrentRequests(self, futures, maxRequests):
        """
        Blocking function that waits until we can add more futures.

        It is in charge of marking requests as fuzzed once completed.

        Args:
            futures: futures as defined in `fuzzButtonClicked`
            maxRequests: maximum requests that should be pending at this time. If we have more futures than this number, this function will block until the situation changes. We check for changes by calling `isDone()` on each of the available futures.

        Return:
            int: number of exceptions thrown during scan. 0 means no errors.
        """
        nbExceptions = 0
        while len(futures) > maxRequests:
            utility.sleep(self.state, 0.5)
            for tuple in futures:
                endpoint, request, frm_futures = tuple
                request_done = False
                for future in frm_futures:
                    if future.isDone():
                        try:
                            future.get()
                        except ExecutionException as exc:
                            logging.error("Failure fuzzing %s" % endpoint.url, exc_info=True)
                            sendMessageToSlack(self.callbacks, "Failure fuzzing %s, exception: %s" % (endpoint.url, exc.cause))

                            nbExceptions += 1

                        frm_futures.remove(future)

                    if len(frm_futures) == 0:
                        request_done = True

                if request_done:
                    futures.remove(tuple)
                    resend_request_model(self.state, self.callbacks, request)

                    textAreaText = self.state.sessionCheckTextarea.text
                    sessionCheckReproducible, _ = resend_session_check(self.state, self.callbacks, textAreaText)

                    if request.wasReproducible() and sessionCheckReproducible:
                        self.state.endpointTableModel.setFuzzed(endpoint, True)
                        log("Finished fuzzing %s" % endpoint.url)
                    elif not request.wasReproducible():
                        log("Fuzzing complete but did not mark as fuzzed because no longer reproducible at %s." % endpoint.url)
                    else:
                        log("Fuzzing complete but did not mark as fuzzed because the session check request is no longer reproducible.")
                        raise SessionCheckNotReproducibleException("Base request no longer reproducible.")

                    break

        return nbExceptions

    @utility.LogDecorator()
    def fuzzRequestModel(self, request):
        """
        Sends a RequestModel to be fuzzed by burp.

        Burp has a helper function for running active scans, however I am not using it for two reasons. Firstly, as of 2.x the mechanism for configuring scans got broken in a re-shuffle of burp code. Secondly, burp's session handling for large scans is not perfect, once the session expires the scan continues to fuzz requests with an expired session, and implementing my own session handling on top of IScannerCheck objects is not possible due to a bug in getStatus() where requests that have errored out still have a "scanning" status. If these issues are resolved we can get rid of this workaround.

        We work around this by importing extensions' JAR files and interacting with them using the same APIs that burp uses.

        Args:
            request: an instance of RequestModel.
        """
        utility.sleep(self.state, 0.2)

        insertionPointsGenerator = InsertionPointsGenerator(self.callbacks)

        futures = []
        for name, extension in self.extensions:
            for activeScanner in extension.getScannerChecks():
                if name == "shelling":
                    onlyParameters = True
                else:
                    onlyParameters = False

                insertionPoints = insertionPointsGenerator.getInsertionPoints(request, onlyParameters)

                for insertionPoint in insertionPoints:
                    runnable = PythonFunctionRunnable(self.doActiveScan, args=[activeScanner, request.repeatedHttpRequestResponse, insertionPoint])
                    futures.append(self.state.fuzzExecutorService.submit(runnable))

            for factory in extension.getContextMenuFactories():
                if name == "paramminer":
                    menuItems = factory.createMenuItems(ContextMenuInvocation([request.repeatedHttpRequestResponse]))
                    for menuItem in menuItems:
                        # trigger "Guess headers/parameters/JSON!" functionality.
                        runnable = PythonFunctionRunnable(menuItem.doClick)
                        futures.append(self.state.fuzzExecutorService.submit(runnable))

        return futures

    @utility.LogDecorator()
    def doActiveScan(self, scanner, httpRequestResponse, insertionPoint):
        """
        Performs an active scan and stores issues found.

        Because the scanner fails sometimes with random errors when HTTP requests timeout and etcetera, we retry a couple of times. This allows us to scan faster because we can be more resilient to errors.

        Args:
            scanner: a IScannerCheck object as returned by extension.getActiveScanners().
            httpRequestResponse: the value to pass to doActiveScan. This should be the modified request, i.e. repeatedHttpRequestResponse.
            insertionPoint: the insertionPoint to scan.
        """
        retries = 5
        while retries > 0:
            utility.sleep(self.state, 1)
            try:
                issues = scanner.doActiveScan(httpRequestResponse, insertionPoint)
                with self.lock:
                    if issues:
                        for issue in issues:
                            self.callbacks.addScanIssue(issue)

                break
            except (java.lang.Exception, java.lang.NullPointerException):
                retries -= 1
                logging.error("Java exception while fuzzing individual param, retrying it. %d retries left." % retries, exc_info=True)
            except:
                retries -= 1
                logging.error("Exception while fuzzing individual param, retrying it. %d retries left." % retries, exc_info=True)

class InsertionPointsGenerator(object):
    """
    Generates insertion points given a request.
    """

    def __init__(self, callbacks):
        """
        Main constructor.

        Args:
            callbacks: the burp callbacks object.
        """
        self.callbacks = callbacks

    def getInsertionPoints(self, request, onlyParameters):
        """
        Gets IScannerInsertionPoint for indicating active scan parameters. See https://portswigger.net/burp/extender/api/burp/IScannerInsertionPoint.html

        Uses a custom implementation of the IScannerInsertionPoint because the default helper function at `makeScannerInsertionPoint` doesn't let you specify the parameter type. The parameter type is necessary to perform modifications to the payload in order to perform proper injection, such as not using unescaped quotes when inserting into a JSON object as this will result in a syntax error.

        Args:
            request: the request to generate insertion points for.
            onlyParameters: whether to fuzz only get and body parameters. Doesn't fuzz cookies, path parameters nor headers. This saves time when running shelling which takes a long time due to a long payload list.
        """
        parameters = request.repeatedAnalyzedRequest.parameters

        insertionPoints = []
        for parameter in parameters:

            if parameter.type == IParameter.PARAM_COOKIE and onlyParameters:
                continue

            insertionPoint = ScannerInsertionPoint(self.callbacks, request.repeatedHttpRequestResponse.request, parameter.name, parameter.value, parameter.type, parameter.valueStart, parameter.valueEnd)
            insertionPoints.append(insertionPoint)

        if onlyParameters:
            return insertionPoints

        for pathInsertionPoint in self.getPathInsertionPoints(request):
            insertionPoints.append(pathInsertionPoint)

        for headerInsertionPoint in self.getHeaderInsertionPoints(request):
            insertionPoints.append(headerInsertionPoint)

        return insertionPoints

    def getHeaderInsertionPoints(self, request):
        """
        Gets header insertion points.

        This means that for a header like:

        ```
        GET / HTTP/1.1
        Host: header.com
        Random-header: lel-value

        ```

        It would generate two insertion points corresponding to the headers.

        Args:
            request: the request to analyze.
        """
        headers = request.repeatedAnalyzedRequest.headers

        lineStartOffset = 0
        insertionPoints = []
        for nb, header in enumerate(headers):

            if nb > 0:
                headerSeparator = ":"

                splat = header.split(headerSeparator)
                headerName = splat[0]

                headerValue = splat[1]
                startedWithSpace = headerValue.startswith(" ")
                headerValue = headerValue.lstrip()

                startOffset = lineStartOffset + len(headerName) + len(headerSeparator)
                if startedWithSpace:
                    startOffset += 1

                endOffset = startOffset + len(headerValue)

                insertionPoint = ScannerInsertionPoint(self.callbacks, request.repeatedHttpRequestResponse.request, headerName, headerValue, IScannerInsertionPoint.INS_HEADER, startOffset, endOffset)
                insertionPoints.append(insertionPoint)

            lineStartOffset += len(header) + len("\r\n")

        return insertionPoints

    def getPathInsertionPoints(self, request):
        """
        Gets folder insertion points.

        This means that for a URL such as /folder/folder/file.php it would generate three insertion points: one for each folder and one for the filename.

        Args:
            request: the request to generate the insertion points for.

        Return:
            list: the IScannerInsertionPoint objects.
        """
        firstLine = request.repeatedAnalyzedRequest.headers[0]
        startOffset = None
        endOffset = None
        insertionPoints = []

        if " / " in firstLine:
            return []

        for offset, char in enumerate(firstLine):
            if char in ["/", " ", "?"]:
                if not startOffset:
                    if char == "/":
                        startOffset = offset + 1
                else:
                    endOffset = offset
                    value = firstLine[startOffset:endOffset]
                    type = IScannerInsertionPoint.INS_URL_PATH_FOLDER if char == "/" else IScannerInsertionPoint.INS_URL_PATH_FILENAME

                    insertionPoint = ScannerInsertionPoint(self.callbacks, request.repeatedHttpRequestResponse.request, "pathParam", value, type, startOffset, endOffset)

                    insertionPoints.append(insertionPoint)
                    startOffset = offset + 1

                    if char in [" ", "?"]:
                        break

        return insertionPoints
