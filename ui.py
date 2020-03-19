from burp import IScannerInsertionPoint, IParameter
from fuzz import FuzzRunner
from implementations import MessageEditorController, HttpService, ScannerInsertionPoint, ContextMenuInvocation
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
from tables import Table, CellHighlighterRenderer, TableMouseAdapter
from threading import Lock
from utility import apply_rules, get_header, log, sendMessageToSlack, importBurpExtension, LogDecorator, PythonFunctionRunnable, resend_request_model
from utility import REPLACE_HEADER_NAME, NoSuchHeaderException, ShutdownException
import jarray
import logging
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

        scopeText = callbacks.loadExtensionSetting("scopes")
        state.scopeTextArea.setText(scopeText)

        scope.add(title)
        scope.add(refresh)
        scope.add(textarea)

        if scopeText:
            refresh.doClick() # refresh automatically to save users one click.

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
            self.state.fuzzExecutorService = Executors.newFixedThreadPool(16)

            # Beware: if the second argument to two of these importBurpExtension calls is the same, the same extension will be loaded twice. The solution is to recompile the JARs so that the classes do not have the same name.
            log("[+] Loading Backslash Powered Scanner")
            self.extensions.append(("bps", utility.importBurpExtension("lib/backslash-powered-scanner-fork.jar", 'burp.BackslashBurpExtender', burpCallbacks)))

            log("[+] Loading SHELLING")
            self.extensions.append(("shelling", utility.importBurpExtension("lib/shelling.jar", 'burp.BurpExtender', burpCallbacks)))

            log("[+] Loading ParamMiner")
            self.extensions.append(("paramminer", utility.importBurpExtension("lib/param-miner-fork.jar", 'paramminer.BurpExtender', burpCallbacks)))

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

        self.state.endpointTableModel.fireTableDataChanged()

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

        if not rule:
            return

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
                runnable = PythonFunctionRunnable(resend_request_model, args=[self.state, self.burpCallbacks, request])
                futures.append(self.state.executorService.submit(runnable))
                nb += 1

        while len(futures) > 0:
            utility.sleep(self.state, 1)
            resendAllButton.setText("%s remaining" % (len(futures)))

            for future in futures:
                if future.isDone():
                    futures.remove(future)

        resendAllButton.setText("Resent")

    def fuzzButtonClicked(self, event):
        """
        Handles clicks to the FUZZ button.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        if self.state.status == STATUS_FAILED:
            self.messageDialog("Confirm status check button says OK.")
            return

        fuzzButton = event.source
        fuzzButton.setText("Fuzzing...")

        try:
            fuzzRunner = FuzzRunner(self.state, self.burpCallbacks, self.extensions)
            nbFuzzedTotal, nbExceptions = fuzzRunner.run()
        except ShutdownException:
                log("Scan shutdown.")
                return
        except:
            if utility.INSIDE_UNIT_TEST:
                raise

            msg = "Scan failed due to an unknown exception."
            sendMessageToSlack(self.burpCallbacks, msg)
            logging.error(msg, exc_info=True)
            fuzzButton.setText("Fuzz fail.")
            return

        fuzzButton.setText("FUZZ")

        if nbFuzzedTotal > 0 and nbExceptions == 0:
            sendMessageToSlack(self.burpCallbacks, "Scan finished normally with no exceptions.")
        elif nbFuzzedTotal > 0:
            sendMessageToSlack(self.burpCallbacks, "Scan finished with %s exceptions." % nbExceptions)
