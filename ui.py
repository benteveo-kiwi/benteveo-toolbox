from burp import IScannerInsertionPoint, IParameter
from implementations import MessageEditorController, HttpService, ScannerInsertionPoint
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Component
from java.awt import Dimension
from java.awt import FlowLayout
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.lang import Class
from java.lang import Runnable
from java.lang import String
from java.lang import Thread
from java.util.concurrent import Executors, ExecutionException
from javax.swing import BorderFactory
from javax.swing import Box
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JLabel
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import SwingUtilities
from tables import Table, CellHighlighterRenderer, TableMouseAdapter, NoResponseException
from threading import Lock
from utility import apply_rules, get_header, log, sendMessageToSlack, importBurpExtension
from utility import REPLACE_HEADER_NAME, NoSuchHeaderException
import jarray
import java.lang.Exception
import logging
import re
import sys
import time
import traceback
import utility

STATUS_OK = 0
STATUS_FAILED = 1

class InvalidInputException(Exception):
    """
    Raised when a user inputs something invalid into a form.
    """
    pass

class ShutdownException(Exception):
    """
    Raised on threads to cause a failure that will trigger the thread to naturally die.
    """
    pass

class ToolboxUI():

    BUTTON_WIDTH = 140
    BUTTON_HEIGHT = 30
    CONFIG_PAGE_WIDTH = 2000

    def buildUi(self, state, callbacks):
        """
        Handles the building of the UI components using Swing, a UI library.
        """

        self.callbacks = ToolboxCallbacks(state, callbacks)
        state.toolboxCallbacks = self.callbacks

        tabs = JTabbedPane()
        resultsPane = self.buildResultsPane(state, callbacks)
        configPane = self.buildConfigPane(state, callbacks)

        tabs.addTab("Results", resultsPane)
        tabs.addTab("Config", configPane)

        return tabs

    def buildResultsPane(self, state, callbacks):
        """
        Builds the results pane in the confiuration page
        """
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        requestTable = self.buildRequestTable(state, callbacks)
        tabs = self.buildMessageViewer(state, callbacks)

        splitpane.setLeftComponent(requestTable)
        splitpane.setRightComponent(tabs)

        callbacks.customizeUiComponent(requestTable)
        callbacks.customizeUiComponent(tabs)

        return splitpane

    def buildConfigPane(self, state, callbacks):
        """
        Builds the config pane, section per section.
        """
        configPage = Box.createVerticalBox()
        configPage.setBorder(BorderFactory.createLineBorder(Color.black));

        configPage.add(self.buildScope(state, callbacks))
        configPage.add(self.buildReplacementRules(state, callbacks))
        configPage.add(self.buildSessionCheck(state, callbacks))

        return configPage

    def buildScope(self, state, callbacks):
        """
        Builds the scope pane in the configuration page
        """
        scope = JPanel()
        scope.setLayout(None)
        scope.setMaximumSize(Dimension(self.CONFIG_PAGE_WIDTH, 300))

        title = self.getTitle("Scope Selection", 20, 10)

        refresh = self.getButton("Refresh", 20, 50)
        refresh.addActionListener(self.callbacks.refreshButtonClicked)

        textarea = self.getTextArea()
        state.scopeTextArea = textarea.viewport.view
        state.scopeTextArea.setText(callbacks.loadExtensionSetting("scopes"))

        scope.add(title)
        scope.add(refresh)
        scope.add(textarea)

        return scope

    def buildReplacementRules(self, state, callbacks):
        """
        Builds the replacement rules section in the configuration page
        """
        rules = JPanel()
        rules.setLayout(None)
        rules.setMaximumSize(Dimension(self.CONFIG_PAGE_WIDTH, 300))

        title = self.getTitle("Replacement Rules", 20, 10)

        add = self.getButton("Add", 20, 50)
        add.addActionListener(self.callbacks.addButtonClicked)

        edit = self.getButton("Edit", 20, 90)
        edit.addActionListener(self.callbacks.editButtonClicked)
        delete = self.getButton("Delete", 20, 130)
        delete.addActionListener(self.callbacks.deleteButtonClicked)

        table = Table(state.replacementRuleTableModel)
        tableView = JScrollPane(table)
        tableView.setBounds(180, 50, 800, 240)

        rules.add(title)
        rules.add(add)
        rules.add(edit)
        rules.add(delete)
        rules.add(tableView)

        try:
            storedReplacementRules = callbacks.loadExtensionSetting("replacementRules")
            if storedReplacementRules:
                state.replacementRuleTableModel.importJsonRules(storedReplacementRules)
            else:
                log("No replacement rules stored.")
        except (ValueError, KeyError):
            log("Invalid replacement rules stored. Ignoring.")
            pass

        return rules

    def buildSessionCheck(self, state, callbacks):
        """
        Builds the session check portion of the config page
        """
        rules = JPanel()
        rules.setLayout(None)
        rules.setMaximumSize(Dimension(self.CONFIG_PAGE_WIDTH, 300))

        title = self.getTitle("Session Check", 20, 10)

        check = self.getButton("Check", 20, 50)
        check.addActionListener(self.callbacks.checkButtonClicked)

        resendAll = self.getButton("Resend ALL", 20, 90)
        resendAll.addActionListener(self.callbacks.resendAllButtonClicked)

        fuzz = self.getButton("FUZZ", 20, 130)
        fuzz.addActionListener(self.callbacks.fuzzButtonClicked)

        textarea = self.getTextArea()
        state.sessionCheckTextarea = textarea.viewport.view
        state.sessionCheckTextarea.setText(callbacks.loadExtensionSetting("scopeCheckRequest"))

        rules.add(title)
        rules.add(check)
        rules.add(resendAll)
        rules.add(fuzz)
        rules.add(textarea)

        return rules

    def getButton(self, label, positionX, positionY):
        """
        Creates a JButton with a specific label and position
        """
        button = JButton(label)
        button.setBounds(positionX, positionY, self.BUTTON_WIDTH, self.BUTTON_HEIGHT)

        return button

    def getTextArea(self):
        """
        Creates a scrollable textarea
        """
        textarea = JTextArea()
        textarea.setBounds(180, 50, 800, 240)
        scrollPane = JScrollPane(textarea)
        scrollPane.setBounds(180, 50, 800, 240)

        return scrollPane

    def getTitle(self, content, positionX, positionY):
        """
        Creates a title for the configuration page.
        """
        title = JLabel("<html><h2>" + content + "</h2></html>")
        title.setBounds(positionX, positionY, 1000, 30)

        return title

    def buildRequestTable(self, state, callbacks):
        """
        Builds the request list on the results page on the right.
        """
        splitpane = JSplitPane()
        splitpane.setDividerLocation(1000)

        endpointTable = Table(state.endpointTableModel)
        endpointTable.setDefaultRenderer(Class.forName('java.lang.Object'), CellHighlighterRenderer(state))

        endpointTable.getColumnModel().getColumn(0).setPreferredWidth(15)
        endpointTable.getColumnModel().getColumn(1).setPreferredWidth(500)
        endpointTable.setAutoCreateRowSorter(True)
        endpointTable.addMouseListener(TableMouseAdapter())

        endpointView = JScrollPane(endpointTable)
        callbacks.customizeUiComponent(endpointTable)
        callbacks.customizeUiComponent(endpointView)

        requestTable = Table(state.requestTableModel)
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(500)

        requestView = JScrollPane(requestTable)
        callbacks.customizeUiComponent(requestTable)
        callbacks.customizeUiComponent(requestView)

        splitpane.setLeftComponent(endpointView)
        splitpane.setRightComponent(requestView)

        return splitpane

    def buildMessageViewer(self, state, callbacks):
        """
        Builds the panel that allows users to view requests on the results page.

        Args:
            state: the state object.
            callbacks: the burp callbacks object.
        """

        tabs = JTabbedPane()

        original = JSplitPane()
        original.setDividerLocation(1000)

        modified = JSplitPane()
        modified.setDividerLocation(1000)

        originalRequestEditor = MessageEditorController(state, "original")
        repeatedRequestEditor = MessageEditorController(state, "repeated")

        state.originalRequestViewer = callbacks.createMessageEditor(originalRequestEditor, False)
        state.originalResponseViewer = callbacks.createMessageEditor(originalRequestEditor, False)

        state.repeatedRequestViewer = callbacks.createMessageEditor(repeatedRequestEditor, False)
        state.repeatedResponseViewer = callbacks.createMessageEditor(repeatedRequestEditor, False)

        original.setLeftComponent(state.originalRequestViewer.getComponent())
        original.setRightComponent(state.originalResponseViewer.getComponent())

        modified.setLeftComponent(state.repeatedRequestViewer.getComponent())
        modified.setRightComponent(state.repeatedResponseViewer.getComponent())

        tabs.addTab("Original", original)
        tabs.addTab("Modified", modified)

        return tabs

class PythonFunctionRunnable(Runnable):
    """
    A python implementation of Runnable.
    """
    def __init__(self, method, args=[], kwargs={}):
        """
        Stores these variables for when the run() method is called.

        Args:
            method: the method to call
            args: args to pass
            kwargs: kwargs to pass
        """
        self.method = method
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """
        Method that gets called by the new thread.
        """
        try:
            self.method(*self.args, **self.kwargs)
        except ShutdownException:
            log("Thread shutting down")
            raise
        except:
            logging.exception("Exception in thread")

class NewThreadCaller(object):
    """
    Superclass of callbacks that ensures callbacks are run on their own thread. Only methods that have "Clicked" at the end are affected by this.

    This is because Swing callbacks are made on the main UI thread, which results in complex computations causing a hang on the UI. Instead of adding something on each callback, this object handles this in a generic way for all methods.
    """

    insideAUnitTest = False

    def __getattribute__(self, name):
        """
        This method gets called when somebody tries to access a method.

        If we're not testing, we spawn the method in a new thread. If testing it just gets called in the same thread.

        Args:
            name: the name of the potential method.
        """
        attr = object.__getattribute__(self, name)

        if utility.INSIDE_UNIT_TEST:
            return attr

        if hasattr(attr, '__call__') and name.endswith("Clicked"):
            def newfunc(*args, **kwargs):
                runnable = PythonFunctionRunnable(attr, args, kwargs)
                Thread(runnable).start()
            return newfunc
        else:
            return attr

class ToolboxCallbacks(NewThreadCaller):
    """
    Handles all callbacks.
    """
    def __init__(self, state, burpCallbacks):
        """
        Main constructor. Creates an instance of a FixedThreadPool for threading operations, such as issuing multiple HTTP requests. All calls to this class to methods that end in "Clicked" are made in an independent thread to avoid locking up the Burp UI.

        Args:
            state: the state object.
            burpCallbacks: the burp callbacks object.
        """

        self.state = state
        self.burpCallbacks = burpCallbacks
        self.lock = Lock()
        self.extensions = []

        self.maxConcurrentRequests = 8

        # Avoid instantiating during unit test as it is not needed.
        if not utility.INSIDE_UNIT_TEST:
            self.state.executorService = Executors.newFixedThreadPool(16)
            self.state.perRequestExecutorService = Executors.newFixedThreadPool(self.maxConcurrentRequests)

            # if the second argument to two of these importBurpExtension calls is the same, the same extension will be loaded twice due to caching issues. The solution is to recompile the whole jar so that the classes do not have the same name.
            log("[+] Loading Backslash Powered Scanner")
            self.extensions.append(("bps", utility.importBurpExtension("lib/backslash-powered-scanner-fork.jar", 'burp.BackslashBurpExtender', burpCallbacks)))
            log("[+] Loading SHELLING")
            self.extensions.append(("shelling", utility.importBurpExtension("lib/shelling.jar", 'burp.BurpExtender', burpCallbacks)))

    def refreshButtonClicked(self, event):
        """
        Handles click of refresh button. This reloads the results page with the new scope.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        self.state.endpointTableModel.clear()

        scopes = self.state.scopeTextArea.text
        self.burpCallbacks.saveExtensionSetting("scopes", scopes)

        scope_urls = scopes.split("\n")
        for url in scope_urls:
            url = url.strip()
            if not url:
                continue

            requests = self.burpCallbacks.getSiteMap(url)
            for request in requests:
                self.state.endpointTableModel.add(request)

        button = event.source
        button.setText("Refreshed (%s)" % (str(len(self.state.endpointTableModel.endpoints))))

    def buildAddEditPrompt(self, typeValue=None, searchValue=None, replacementValue=None):
        """
        Builds the replacement rules add/edit prompt.

        Args:
            typeValue: the value that will be set on the type JLabel.
            searchValue: the value that will be set on the search JLabel.
            replacementValue: the value that will be set on the replacement JLabel.

        Return:
            tuple: (type, search, replacement) as input by user.
        """
        panel = Box.createVerticalBox()

        typeLabel = JLabel("Replacement type")
        type = JComboBox([REPLACE_HEADER_NAME])
        searchLabel = JLabel("Header Name / Search String")
        search = JTextField()
        replaceLabel = JLabel("Replacement Value")
        replacement = JTextField()

        panel.add(typeLabel)
        panel.add(type)
        panel.add(searchLabel)
        panel.add(search)
        panel.add(replaceLabel)
        panel.add(replacement)

        if typeValue:
            type.setSelectedItem(typeValue)

        if searchValue:
            search.text = searchValue

        if replacementValue:
            replacement.text = replacementValue

        title = "Add Replacement Rule" if type == None else "Edit Replacement Rule"

        result = JOptionPane.showConfirmDialog(None, panel, "Add Replacement Rule", JOptionPane.PLAIN_MESSAGE)

        if result == JOptionPane.OK_OPTION:
            if search.text.strip() == "":
                self.messageDialog("Header name must be non-blank.")
                raise InvalidInputException()
            else:
                return type.selectedItem, search.text, replacement.text
        else:
            raise InvalidInputException()

    def messageDialog(self, message):
        """
        Convenience function for displaying a message to the user.

        Args:
            message: message to display.
        """
        JOptionPane.showMessageDialog(None, message)

    def addButtonClicked(self, event):
        """
        Handles click of the replacement rule add button.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        try:
            type, search, replacement = self.buildAddEditPrompt()
        except InvalidInputException:
            return

        self.state.replacementRuleTableModel.add(type, search, replacement)
        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def editButtonClicked(self, event):
        """
        Handles click of the edit button.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        rule = self.state.replacementRuleTableModel.selected

        try:
            type, search, replacement = self.buildAddEditPrompt(rule.type, rule.search, rule.replacement)
        except InvalidInputException:
            return

        self.state.replacementRuleTableModel.edit(rule.id, type, search, replacement)
        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def deleteButtonClicked(self, event):
        """
        Handles click of the delete button.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        rule = self.state.replacementRuleTableModel.selected
        self.state.replacementRuleTableModel.delete(rule.id)

        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def checkButtonClicked(self, event):
        """
        Gets called when a user clicks the check button. Repeats the request with the modifications made and assesses whether the result is positive or negative.

        Normalizes the newlines in the textarea to make them compatible with burp APIs and then converts them into a binary string.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """

        textAreaText = self.state.sessionCheckTextarea.text

        checkButton = event.source
        checkButton.setText("Checking...")

        self.burpCallbacks.saveExtensionSetting("scopeCheckRequest", textAreaText)

        baseRequestString = re.sub(r"(?!\r)\n", "\r\n", textAreaText)
        baseRequest = self.burpCallbacks.helpers.stringToBytes(baseRequestString)

        try:
            hostHeader = get_header(self.burpCallbacks, baseRequest, "host")
        except NoSuchHeaderException:
            self.messageDialog("Check request failed: no Host header present in session check request.")
            self.checkButtonSetFail(checkButton)
            return

        target = self.burpCallbacks.helpers.buildHttpService(hostHeader, 443, "https")

        nbModified, modifiedRequest = apply_rules(self.burpCallbacks, self.state.replacementRuleTableModel.rules, baseRequest)
        if nbModified == 0:
            log("Warning: No modifications made to check request.")

        response = self.burpCallbacks.makeHttpRequest(target, modifiedRequest)
        analyzedResponse = self.burpCallbacks.helpers.analyzeResponse(response.response)

        if analyzedResponse.statusCode == 200:
            checkButton.setText("Check: OK")
            self.state.status = STATUS_OK
        else:
            self.messageDialog("Check request failed: response was not 200 OK, was '%s'." % str(analyzedResponse.statusCode))
            self.checkButtonSetFail(checkButton)

    def checkButtonSetFail(self, checkButton):
        """
        Convenience function to make the check button failed.

        Args:
            checkButton: the JButton instance corresponding to the check button.
        """
        checkButton.setText("Check: FAILED")
        self.state.status = STATUS_FAILED

    def resendAllButtonClicked(self, event):
        """
        Gets called when the user clicks the `Resend ALL` button. This initiates the main IDOR checking.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        if self.state.status == STATUS_FAILED:
            self.messageDialog("Confirm status check button says OK.")
            return

        endpoints = self.state.endpointTableModel.endpoints
        resendAllButton = event.source

        futures = []
        nb = 0
        for key in endpoints:
            endpoint = endpoints[key]
            for request in endpoint.requests:
                runnable = PythonFunctionRunnable(self.resendRequestModel, args=[request])
                futures.append(self.state.executorService.submit(runnable))
                nb += 1

        while len(futures) > 0:
            self.sleep(1)
            resendAllButton.setText("%s remaining" % (len(futures)))

            for future in futures:
                if future.isDone():
                    futures.remove(future)

        resendAllButton.setText("Resent")

    def resendRequestModel(self, request):
        """
        Resends a request model and performs basic analysis on whether it responds with the same state and status code.

        This method gets called from each thread. Operations on the global state need to be thread-safe.

        Args:
            request: the RequestModel to resend.
        """
        target = request.httpRequestResponse.httpService

        path = request.analyzedRequest.url.path
        if "logout" in path:
            log("Ignoring request to %s to avoid invalidating the session." % path)
            return

        nbModified, modifiedRequest = apply_rules(self.burpCallbacks,
                                                self.state.replacementRuleTableModel.rules,
                                                request.httpRequestResponse.request)
        if nbModified == 0:
            log("Warning: Request for '%s' endpoint was not modified." % path)

        newResponse = self.burpCallbacks.makeHttpRequest(target, modifiedRequest)
        self.state.endpointTableModel.update(request, newResponse)

    def fuzzButtonClicked(self, event):
        """
        Handles clicks to the FUZZ button.

        We attempt to fuzz only one request per endpoint, using our own criteria to differentiate between endpoints as defined in `EndpontTableModel.generateEndpointHash`. For each endpoint, we iterate through requests until we can find a single request whose status code is the same between both the original and the repeated request, we only fuzz once. Note this tool will only succeed if the user has clicked the check button.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        if self.state.status == STATUS_FAILED:
            self.messageDialog("Confirm status check button says OK.")
            return

        endpoints = self.state.endpointTableModel.endpoints

        fuzzButton = event.source
        fuzzButton.setText("Fuzzing...")

        futures = []
        endpointsNotReproducibleCount = 0
        nbFuzzedTotal = 0
        try:
            for key in endpoints:
                endpoint = endpoints[key]

                if endpointsNotReproducibleCount >= 10:
                    log("10 endpoints in a row not endpointsNotReproducibleCount")
                    sendMessageToSlack("10 endpoints in a row not reproducible, bailing from the current scan.")
                    break

                if endpoint.fuzzed:
                    continue

                fuzzed = False
                for request in endpoint.requests:
                    self.sleep(0.2)
                    try:
                        self.resendRequestModel(request)
                    except NoResponseException:
                        continue

                    if request.wasReproducible():
                        endpointsNotReproducibleCount = 0
                        nbFuzzedTotal += 1

                        runnable = PythonFunctionRunnable(self.fuzzRequestModel, args=[request])
                        futures.append((endpoint, request, self.state.perRequestExecutorService.submit(runnable)))

                        fuzzed = True
                        break

                if not fuzzed:
                    endpointsNotReproducibleCount += 1
                    log("Did not fuzz '%s' because no reproducible requests are possible with the current replacement rules" % endpoint.url)

                self.checkMaxConcurrentRequests(futures, self.maxConcurrentRequests)

            self.checkMaxConcurrentRequests(futures, 1) # ensure all requests are `isDone()`
        except:
            msg = "Scan failed due to an unknown exception."
            sendMessageToSlack(msg)
            logging.exception(msg)

        fuzzButton.setText("FUZZ")

        if nbFuzzedTotal > 0:
            sendMessageToSlack("Scan finished normally.")


    def checkMaxConcurrentRequests(self, futures, maxRequests):
        """
        Blocking function that waits until we can make more requests.

        It is in charge of marking requests as fuzzed once completed.

        Args:
            futures: futures as defined in `fuzzButtonClicked`
            maxRequests: maximum requests that should be pending at this time.
        """
        while len(futures) >= maxRequests:
            self.sleep(1)
            for tuple in futures:
                endpoint, request, future = tuple
                if future.isDone():
                    futures.remove(tuple)

                    try:
                        future.get()
                    except ExecutionException:
                        log("Failed to fuzz %s" % endpoint.url)
                        logging.error("Failure fuzzing %s" % endpoint.url, exc_info=True)
                        continue

                    self.resendRequestModel(request)
                    if request.wasReproducible():
                        self.state.endpointTableModel.setFuzzed(endpoint, True)
                        log("Finished fuzzing %s" % endpoint.url)
                    else:
                        log("Fuzzing complete but did not mark as fuzzed becauase no longer reproducible at %s." % endpoint.url)

                    break

    def fuzzRequestModel(self, request):
        """
        Sends a RequestModel to be fuzzed by burp.

        Burp has a helper function for running active scans, however I am not using it for two reasons. Firstly, as of 2.x the mechanism for configuring scans got broken in a re-shuffle of burp code. Secondly, burp's session handling for large scans is not perfect, once the session expires the scan continues to fuzz requests with an expired session, and implementing my own session handling on top of IScannerCheck objects is not possible due to a bug in getStatus() where requests that have errored out still have a "scanning" status. If these issues are resolved we can get rid of this workaround.

        We work around this by importing Backslash powered scanner's FastScan and calling it directly https://github.com/PortSwigger/backslash-powered-scanner/blob/c861d56a3b84e4720bb0c352a22999012a7b2bc3/src/burp/BurpExtender.java#L55. We maintain a fork of BPS benteveo-kiwi for making private classes public.

        Args:
            request: an instance of RequestModel.
        """
        self.sleep(0.2)

        for name, extension in self.extensions:
            for activeScanner in extension.getScannerChecks():
                if name == "shelling":
                    onlyParameters = True
                else:
                    onlyParameters = False

                insertionPoints = self.getInsertionPoints(request, onlyParameters)

                futures = []
                for insertionPoint in insertionPoints:
                    runnable = PythonFunctionRunnable(self.doActiveScan, args=[activeScanner, request.httpRequestResponse, insertionPoint])
                    futures.append(self.state.executorService.submit(runnable))

        while len(futures) > 0:
            self.sleep(1)

            for future in futures:
                if future.isDone():
                    future.get()
                    futures.remove(future)

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

            insertionPoint = ScannerInsertionPoint(self.burpCallbacks, request.repeatedHttpRequestResponse.request, parameter.name, parameter.value, parameter.type, parameter.valueStart, parameter.valueEnd)
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

                insertionPoint = ScannerInsertionPoint(self.burpCallbacks, request.repeatedHttpRequestResponse.request, headerName, headerValue, IScannerInsertionPoint.INS_HEADER, startOffset, endOffset)
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

                    insertionPoint = ScannerInsertionPoint(self.burpCallbacks, request.repeatedHttpRequestResponse.request, "pathParam", value, type, startOffset, endOffset)

                    insertionPoints.append(insertionPoint)
                    startOffset = offset + 1

                    if char in [" ", "?"]:
                        break

        return insertionPoints


    def doActiveScan(self, scanner, httpRequestResponse, insertionPoint):
        """
        Performs an active scan and stores issues found.

        Because the scanner fails sometimes with random errors when HTTP requests timeout and etcetera, we retry a couple of times. This allows us to scan faster because we can be more resilient to errors.

        Args:
            scanner: a IScannerCheck object as returned by extension.getActiveScanners().
            httpRequestResponse: the value to pass to doActiveScan
            insertionPoint: the insertionPoint to scan.
        """
        retries = 5
        while retries > 0:
            self.sleep(1)
            try:
                issues = scanner.doActiveScan(httpRequestResponse, insertionPoint)
                break
            except java.lang.Exception:
                retries -= 1
                logging.error("Java exception while fuzzing individual param, retrying it. %d retries left." % retries, exc_info=True)

        with self.lock:
            if issues:
                for issue in issues:
                    sendMessageToSlack("Found something interesting! apparently '%s'. Do you want to check it out?" % (issue.issueName))
                    self.burpCallbacks.addScanIssue(issue)

    def sleep(self, sleepTime):
        """
        Sleeps for a certain time. Checks for state.shutdown and if it is true raises an unhandled exception that crashes the thread.

        Args:
            sleepTime: the time in seconds.
        """
        if self.state.shutdown:
            log("Thread shutting down.")
            raise ShutdownException()

        time.sleep(sleepTime)
