from burp import IBurpExtender
from implementations import Tab, HttpListener, MessageEditorController, ExtensionStateListener
from java.util import TimerTask, Timer
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel
from tables import Table
from ui import ToolboxUI, STATUS_FAILED
import logging
import utility

utility.INSIDE_UNIT_TEST = False

class State(object):
    """
    An object that keeps the state of the application. Because Burp's architecture is event driven, I use this object for communication between the different objects that get called on different callbacks.
    """

    def __init__(self):
        self.status = STATUS_FAILED
        self.shutdown = False

class BurpExtender(IBurpExtender):

    def	registerExtenderCallbacks(self, callbacks):
        """
        Burp initialisation function. Gets called when the extension is loaded and
        is in charge of building the UI.

        Args:
            callbacks: contains a burp callbacks object, as documented here https://portswigger.net/burp/extender/api/burp/IBurpCallbacks.html
        """

        utility.setupLogging()

        utility.log("Loaded Benteveo Toolbox v0.3.0")

        state = State()

        # Endpoint table models are in charge of storing and disiplaying information in tables.
        state.endpointTableModel = EndpointTableModel(state, callbacks)
        state.requestTableModel = RequestTableModel(state, callbacks)
        state.replacementRuleTableModel = ReplacementRuleTableModel()

        # ToolboxUI handles building the Swing UI.
        ui = ToolboxUI()
        splitpane = ui.buildUi(state, callbacks)

        # Burp callbacks, to handle interactions with Burp.
        callbacks.addSuiteTab(Tab(splitpane))
        callbacks.registerHttpListener(HttpListener(state, callbacks))
        callbacks.setExtensionName("Benteveo Toolbox")
        callbacks.registerExtensionStateListener(ExtensionStateListener(state));

        # Periodically check for new issues and report to slack.
        issueChecker = IssueChecker(state, callbacks)
        state.timer = Timer()
        state.timer.scheduleAtFixedRate(issueChecker, 1000, 1000)

class IssueChecker(TimerTask):
    """
    Periodically checks for the presence of new issues and reports them to slack.
    """
    def __init__(self, state, callbacks):
        self.state = state
        self.callbacks = callbacks

        self.reportedIssues = self.getAllIssues()

    def getAllIssues(self):
        """
        Gets all issues that are already present at extension load time. This is returned in the form of a dictionary that has the value returned by `getIssueHash()` as the key and true and the value.
        """
        reportedIssues = {}
        issues = self.callbacks.getScanIssues(None)
        for issue in issues:
            hsh = self.getIssueHash(issue)
            reportedIssues[hsh] = True

        return reportedIssues

    def getIssues(self, scopeUrls):
        """
        Gets issues pertaining to the scope that should be reported to Slack.

        Args:
            scopeUrls: the scope urls textarea text, split at new lines. It is an array of URLs with a newline at the end.
        """
        issues = []
        for url in scopeUrls:
            url = url.strip()
            urlIssues = self.callbacks.getScanIssues(url)

            for issue in urlIssues:
                issues.append(issue)

        return issues

    def getIssueHash(self, issue):
        """
        Calculates a unique string derivated from the issue's properties.

        Args:
            issue: an instance of IScanIssue, as documented here: https://portswigger.net/burp/extender/api/burp/IScanIssue.html
        """
        hsh = issue.issueName + "|" + issue.url.toString()
        return hsh

    def run(self):
        """
        Main method. Gets called periodically by the Timer.
        """

        # @TODO: XXX: Re-enable issue notifications. This has been disabled temporarily due to issue #29.
        return

        try:
            try:
                scopeUrls = self.state.scope_urls
            except AttributeError:
                return

            issues = self.getIssues(scopeUrls)

            for issue in issues:
                hsh = self.getIssueHash(issue)

                if hsh not in self.reportedIssues:
                    self.reportIssue(issue)
                    self.reportedIssues[hsh] = True

        except:
            # It's very important to not crash inside a timer.
            logging.error("Error in IssueChecker.", exc_info=True)

    def reportIssue(self, issue):
        """
        Reports issue to Slack channel.

        Args:
            issue: an instance of IScanIssue, as documented here: https://portswigger.net/burp/extender/api/burp/IScanIssue.html
        """
        name = issue.issueName
        url = issue.url.toString()

        message = "New issue found. '%s' at '%s'." % (name, url)

        utility.sendMessageToSlack(self.callbacks, message)
