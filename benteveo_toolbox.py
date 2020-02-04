from burp import IBurpExtender
from implementations import Tab, HttpListener, MessageEditorController, ExtensionStateListener
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel
from tables import Table
from ui import ToolboxUI, STATUS_FAILED
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
