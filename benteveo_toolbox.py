from burp import IBurpExtender
from classes import Table, LogEntry, Tab, HttpListener, TableModel, MessageEditorController, \
    ToolboxUI

class State(object):
    """
    An object that keeps the state of the application. Because Burp's
    architecture is event driven, I use this object for communication between
    the different objects that get called on different callbacks.
    """
    pass

class BurpExtender(IBurpExtender):

    state = None

    def	registerExtenderCallbacks(self, callbacks):
        """
        Burp initialisation function. Gets called when the extension is loaded and
        is in charge of building the UI.
        """
        # add Burp utility functions to state so that they are accessible everywhere.
        state = State()
        state._callbacks = callbacks
        state._helpers = callbacks.getHelpers()
        state.tableModel = TableModel(state)

        # Add required callbacks.
        ui = ToolboxUI()
        splitpane = ui.buildUi(state, callbacks)

        callbacks.addSuiteTab(Tab(splitpane))
        callbacks.registerHttpListener(HttpListener(state))
        callbacks.setExtensionName("Benteveo Toolbox")
