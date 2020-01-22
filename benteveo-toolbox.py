from burp import IBurpExtender
from java.awt import Component
from java.io import PrintWriter
from java.util import List
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from classes import Table, LogEntry, Tab, HttpListener, TableModel, MessageEditorController

class State(object):
    """
    A very important object that keeps the state of the application. Because Burp's
    architecture is event driven, I use this object for communication between the different
    objects that get called on different callbacks.
    """
    pass

class BurpExtender(IBurpExtender):

    state = None

    def	registerExtenderCallbacks(self, callbacks):
        """
        Burp initialisation function. Gets called when the extension is loaded and
        is in charge of building the UI.
        """

        callbacks.setExtensionName("Benteveo Toolbox")

        state = State()

        state._callbacks = callbacks
        state._helpers = callbacks.getHelpers()

        state.tableModel = TableModel(state)

        state._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        logTable = Table(state.tableModel)
        scrollPane = JScrollPane(logTable)
        state._splitpane.setLeftComponent(scrollPane)

        tabs = JTabbedPane()
        messageEditor = MessageEditorController(state)
        state._requestViewer = callbacks.createMessageEditor(messageEditor, False)
        state._responseViewer = callbacks.createMessageEditor(messageEditor, False)
        tabs.addTab("Request", state._requestViewer.getComponent())
        tabs.addTab("Response", state._responseViewer.getComponent())
        state._splitpane.setRightComponent(tabs)

        # customize our UI components
        callbacks.customizeUiComponent(state._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        tab = Tab(state)
        httpListener = HttpListener(state)

        callbacks.addSuiteTab(tab)
        callbacks.registerHttpListener(httpListener)

        return
