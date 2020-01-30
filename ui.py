from implementations import MessageEditorController, HttpService
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Component
from java.awt import Dimension
from java.awt import FlowLayout
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.lang import Runnable
from java.lang import String
from java.lang import Class
from java.lang import Thread
from java.util.concurrent import Executors
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
from tables import Table, CellHighlighterRenderer
from utility import apply_rules, get_header, log
from utility import REPLACE_HEADER_NAME, NoSuchHeaderException
import jarray
import re
import sys
import traceback
import utility

STATUS_OK = 0
STATUS_FAILED = 1

class InvalidInputException(Exception):
    """
    Raised when a user inputs something invalid into a form.
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
            state.replacementRuleTableModel.importJsonRules(storedReplacementRules)
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
        state.checkButton = check

        runAll = self.getButton("Run ALL", 20, 90)
        runAll.addActionListener(self.callbacks.runAllButtonClicked)

        textarea = self.getTextArea()
        state.sessionCheckTextarea = textarea.viewport.view
        state.sessionCheckTextarea.setText(callbacks.loadExtensionSetting("scopeCheckRequest"))

        rules.add(title)
        rules.add(check)
        rules.add(runAll)
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
        endpointTable.setDefaultRenderer(Class.forName('java.lang.Object'), CellHighlighterRenderer())

        endpointTable.getColumnModel().getColumn(0).setPreferredWidth(15)
        endpointTable.getColumnModel().getColumn(1).setPreferredWidth(500)
        endpointTable.setAutoCreateRowSorter(True)

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
        except:
            print "Exception in thread:"
            print sys.exc_info()
            raise

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

        # Avoid instantiating during unit test as it is not needed.
        if not utility.INSIDE_UNIT_TEST:
            self.state.executorService = Executors.newFixedThreadPool(20)

    def refreshButtonClicked(self, event):
        """
        Handles click of refresh button. This reloads the results page with the new scope.
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
        """
        rule = self.state.replacementRuleTableModel.selected
        self.state.replacementRuleTableModel.delete(rule.id)

        self.burpCallbacks.saveExtensionSetting("replacementRules", self.state.replacementRuleTableModel.exportJsonRules())

    def checkButtonClicked(self, event):
        """
        Gets called when a user clicks the check button. Repeats the request with the modifications made and assesses whether the result is positive or negative.

        Normalizes the newlines in the textarea to make them compatible with burp APIs and then converts them into a binary string.
        """

        textAreaText = self.state.sessionCheckTextarea.text

        self.burpCallbacks.saveExtensionSetting("scopeCheckRequest", textAreaText)

        baseRequestString = re.sub(r"(?!\r)\n", "\r\n", textAreaText)
        baseRequest = self.burpCallbacks.helpers.stringToBytes(baseRequestString)

        try:
            hostHeader = get_header(self.burpCallbacks, baseRequest, "host")
        except NoSuchHeaderException:
            self.messageDialog("Check request failed: no Host header present in session check request.")
            self.checkButtonSetFail()
            return

        target = self.burpCallbacks.helpers.buildHttpService(hostHeader, 443, "https")

        nbModified, modifiedRequest = apply_rules(self.burpCallbacks, self.state.replacementRuleTableModel.rules, baseRequest)
        if nbModified > 0:
            response = self.burpCallbacks.makeHttpRequest(target, modifiedRequest)
            analyzedResponse = self.burpCallbacks.helpers.analyzeResponse(response.response)

            if analyzedResponse.statusCode == 200:
                self.state.checkButton.setText("Check: OK")
                self.state.status = STATUS_OK
            else:
                self.messageDialog("Check request failed: response was not 200 OK, was '%s'." % str(analyzedResponse.statusCode))
                self.checkButtonSetFail()
        else:
            self.messageDialog("Check request not issued because no modifications to it were made based on the rules provided by user.")
            self.checkButtonSetFail()

    def checkButtonSetFail(self):
        """
        Convenience function to make the check button failed.
        """
        self.state.checkButton.setText("Check: FAILED")
        self.state.status = STATUS_FAILED

    def runAllButtonClicked(self, event):
        """
        Gets called when the user calls runAll. This initiates the main IDOR checking.

        Args:
            event: the event as passed by Swing.
        """
        if self.state.status == STATUS_FAILED:
            self.messageDialog("Confirm status check button says OK.")
            return

        endpoints = self.state.endpointTableModel.endpoints

        for key in endpoints:
            endpoint = endpoints[key]
            for request in endpoint.requests:
                runnable = PythonFunctionRunnable(self.resendRequestModel, args=[request])
                self.state.executorService.submit(runnable)

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

        if nbModified > 0:
            newResponse = self.burpCallbacks.makeHttpRequest(target, modifiedRequest)
            self.state.endpointTableModel.update(request, newResponse)
        else:
            log("Request was not modified so was not resent.")
