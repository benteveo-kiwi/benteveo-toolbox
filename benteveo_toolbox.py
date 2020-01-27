from burp import IBurpExtender
from implementations import Tab, HttpListener, MessageEditorController
from tables import Table
from ui import ToolboxUI
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel

class State(object):
    """
    An object that keeps the state of the application. Because Burp's architecture is event driven, I use this object for communication between the different objects that get called on different callbacks.
    """
    pass

class BurpExtender(IBurpExtender):

    state = None

    def	registerExtenderCallbacks(self, callbacks):
        """
        Burp initialisation function. Gets called when the extension is loaded and
        is in charge of building the UI.
        """
        state = State()
        state._callbacks = callbacks
        state._helpers = callbacks.getHelpers()

        state.endpointTableModel = EndpointTableModel(state, callbacks)
        state.requestTableModel = RequestTableModel(state, callbacks)
        state.replacementRuleTableModel = ReplacementRuleTableModel()

        ui = ToolboxUI()
        splitpane = ui.buildUi(state, callbacks)

        callbacks.addSuiteTab(Tab(splitpane))
        callbacks.registerHttpListener(HttpListener(state, callbacks))
        callbacks.setExtensionName("Benteveo Toolbox")
