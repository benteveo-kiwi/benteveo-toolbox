from collections import OrderedDict
from java.awt import Color
from java.awt.event import MouseAdapter
from java.lang import Boolean
from java.lang import Class
from java.lang import Integer
from java.lang import String
from javax.swing import JLabel
from javax.swing import JTable
from javax.swing.table import AbstractTableModel
from javax.swing.table import DefaultTableCellRenderer
from models import EndpointModel, RequestModel, ReplacementRuleModel
from threading import Lock
from utility import log
import json
import logging
import sys
import utility
from urlparse import urlparse

class NoResponseException(Exception):
    pass

class Table(JTable):
    """
    Generic table for all tables in our UI.
    """
    def __init__(self, model):
        """
        Constructor function.

        Args:
            model: an object that implements AbstractTableModel, such as RequestTableModel.
        """
        self.model = model

    def changeSelection(self, row, col, toggle, extend):
        """
        Called by Swing when a hacker clicks on a row. Calls selectRow on our TableModel and then calls the parent function to handle highlighting of the clicked cell and etc.

        Args:
            row: row number
            col: col number
            toggle: whether to toggle the selection upon this click.
            extend: whether to extend the selection and have two or more rows selected.
        """
        JTable.changeSelection(self, row, col, toggle, extend)

        try:
            self.model.selectRow(self.convertRowIndexToModel(row))
        except:
            logging.exception("Exception in selectRow")


class TableMouseAdapter(MouseAdapter):
    """
    Adapter for handling mouse clicks to our EndpointsTableModel.
    """

    def mouseClicked(self, event):
        """
        Deals with user clicks.

        Args:
            event: the event as passed by Swing. Documented here: https://docs.oracle.com/javase/7/docs/api/java/util/EventObject.html
        """
        table = event.getSource()
        endpointTableModel = table.getModel()

        rowIndex = table.rowAtPoint(event.point)
        columnIndex = table.columnAtPoint(event.point)

        if columnIndex == 6:
            endpoint = endpointTableModel.getEndpoint(table.convertRowIndexToModel(rowIndex))
            newValue = False if endpoint.fuzzed else True
            endpointTableModel.setFuzzed(endpoint, newValue)

class CellHighlighterRenderer(DefaultTableCellRenderer):
    """
    A renderer for highlighting rows that appear to have IDOR based on a certain set of heuristics, such as whether modified requests have the same length as the original request.
    """

    def __init__(self, state):
        """
        Main constructor.
        """
        self.state = state

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, rowIndex, columnIndex):
        """
        Gets the JComponent for each cell.

        Args:
            table: the table this rendering process corresponds to.
            value: the value of the cell
            isSelected: true if the cell is to be rendered with the selection highlighted; otherwise false
            hasFocus: if true, render cell appropriately. For example, put a special border on the cell, if the cell can be edited, render in the color used to indicate editing
            rowIndex: the rowIndex for this cell
            columnIndex: the columnIndex for this cell.
        """
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, rowIndex, columnIndex)

        modelRow = table.convertRowIndexToModel(rowIndex)

        percentSameStatus = table.model.getValueAt(modelRow, 3)
        percentSameLength = table.model.getValueAt(modelRow, 4)
        hasId = table.model.getValueAt(modelRow, 5)

        idorModeActive = len(self.state.replacementRuleTableModel.rules) > 0

        if (percentSameStatus == 100.0 and percentSameLength == 100.0 and hasId) and idorModeActive:
            if not isSelected:
                comp.setBackground(Color.GREEN)
        else:
            if not isSelected:
                comp.setBackground(Color.WHITE)

        return comp

class EndpointTableModel(AbstractTableModel):
    """
    Handles interactions between raw data and the Swing table.

    Also keeps in the endpoints attribute a list of all known endpoints.
    """

    cols = ["Method", "URL", "#", "% Same Status", "% Same Len", "Has ID", "Fuzzed"]

    def __init__(self, state, callbacks):
        """
        Main constructor.

        Args:
            state: the global state object.
            callbacks: the burp callbacks object.
        """
        self.lock = Lock()
        self.state = state
        self.callbacks = callbacks
        self.endpoints = OrderedDict()
        self.MAX_REQUESTS_PER_ENDPOINT = 200

        try:
            self.fuzzedMetadata = json.loads(self.callbacks.loadExtensionSetting('fuzzed-metadata'))
        except:
            log("Invalid fuzzedMetadata. Ignoring.")
            self.fuzzedMetadata = {}

    def isId(self, folder):
        """
        Checks if this "folder" of the URL path looks like an ID according to our predefined regular expressions.

        Args:
            folder: a part of the file path. E.g. if you have a URL that looks like "images/image.jpg" then this function will be invoked twice, once with "images" and another with "image.jpg".
        """
        for regex in utility.regex:
            if regex.match(folder):
                return True

        return False

    def getRowCount(self):
        """
        Returns the number of rows so that swing can create the table.
        """
        try:
            return len(self.endpoints)
        except:
            return 0

    def getColumnCount(self):
        """
        Returns the number of columns so that Swing can create the table.
        """
        return len(self.cols)

    def getColumnName(self, columnIndex):
        """
        Returns the column name at an individual index so that Swing can create the table.

        Args:
            columnIndex: the column index to get the column name for.
        """
        return self.cols[columnIndex]

    def getEndpoint(self, rowIndex):
        """
        Gets EndpointModel at specific row.

        Because our endpoints item is not a list, we are required to do some extra function calls.

        Args:
            rowIndex: specific row to fetch the EndpointModel for.
        """
        return self.endpoints.values()[rowIndex]

    def getValueAt(self, rowIndex, columnIndex):
        """
        Gets the value for each individual cell.

        Args:
            rowIndex: the y value to fetch the value for.
            columnIndex: the y value to fetch the value for.
        """
        endpointModel = self.getEndpoint(rowIndex)
        if columnIndex == 0:
            return endpointModel.method
        elif columnIndex == 1:
            return endpointModel.url
        elif columnIndex == 2:
            return len(endpointModel.requests)
        elif columnIndex == 3:
            return endpointModel.percentSameStatus
        elif columnIndex == 4:
            return endpointModel.percentSameLength
        elif columnIndex == 5:
            return endpointModel.containsId
        elif columnIndex == 6:
            return endpointModel.fuzzed

    def getColumnClass(self, columnIndex):
        """
        Get column class. Gets called by swing to determine sorting.

        Args:
            columnIndex: the columnIndex to determine the class for.
        """
        if columnIndex in [2, 3, 4]:
            return Integer(0).class
        if columnIndex in [5, 6]:
            return Boolean(True).class
        else:
            return String("").class

    def add(self, httpRequestResponse):
        """
        Adds a http request to the internal state. Note that this method does not trigger a reload of the table. This should be done by the caller to this function once all httpRequestResponses have been added.

        This is called by a click on the "refresh" button, which fetches requests from previous requests. We ignore requests without responses and OPTIONS requests as these don't tend to have IDOR/Fuzzable bugs.

        Args:
            httpRequestResponse: an HttpRequestResponse java object as returned by burp. We'll store it into a file for reduced RAM usage using `IBurpExtenderCallbacks.saveBuffersToTempFiles()`.

        Return:
            boolean: whether the request was added or not. It is not added if method is OPTIONS, if there is no response stored for the original request, or if there are too many requests for this endpoint already.
        """

        with self.lock:

            analyzedRequest = self.callbacks.helpers.analyzeRequest(httpRequestResponse)
            httpRequestResponse = self.callbacks.saveBuffersToTempFiles(httpRequestResponse)

            hash, url, method = self.generateEndpointHash(analyzedRequest)

            if self.isStaticResource(url):
                return False

            if not httpRequestResponse.response:
                return False

            if method == "OPTIONS":
                return False

            try:
                fuzzed = self.fuzzedMetadata[hash]
            except KeyError:
                fuzzed = False

            if hash not in self.endpoints:
                self.endpoints[hash] = EndpointModel(method, url, fuzzed)

            if self.endpoints[hash].nb < self.MAX_REQUESTS_PER_ENDPOINT:
                self.endpoints[hash].add(RequestModel(httpRequestResponse, self.callbacks))
                added = True
            else:
                added = False

            return added

    def isStaticResource(self, url):
        """
        Determines whether this URL belongs to a static resource by analysing the file extension.

        Args:
            url: the URL of the request, without a query string, and after processing by generateEndpointHash.

        Return:
            bool: whether the resource is static and should be ignored.
        """

        ignore_exts = 'js,gif,jpg,png,css,svg,woff,woff2,ttf,jpeg,ico,doc,docx,exe,pdf,xls,pkg,jar,zip,tar.gz,xlsx'.split(',')

        parsed = urlparse(url)
        extension = parsed.path.split('.')[-1]

        return extension in ignore_exts

    def generateEndpointHash(self, analyzedRequest):
        """
        In this endpoint, a hash is a string that is used to group requests.

        Requests that have the same URL and method should be grouped together to avoid duplication of testing effort. For example, "/users/1" and "/users/2" should both generate the same hash.

        We do this by having a collection of regular expressions that are ran against each folder in every URL. If the regex matches, the folder is replaced in such a way that it becomes "/users/{ID}", which results in equal hashes for these kind of endpoints.

        Args:
            analyzedRequest: an analyzed request as returned by helpers.analyzeRequest()
        """
        url = analyzedRequest.url.toString().split("?")[0]
        method = analyzedRequest.method

        hash_url = []
        for folder in url.split("/"):
            if self.isId(folder):
                hash_url.append("{ID}")
            else:
                hash_url.append(folder)

        url = "/".join(hash_url)

        return method + "|" + url, url, method

    def clear(self):
        """
        Gets called when the user clicks the Refresh button in order to clear the state.

        Deletes all currently stored endpoints.
        """

        with self.lock:
            length = len(self.endpoints)
            if length == 0:
                return

            self.endpoints.clear()
            self.fireTableDataChanged()


    def selectRow(self, rowIndex):
        """
        Gets called when a hacker clicks on a row.

        In the case of this particular model, a click triggers an event on the RequestsTableModel that causes it to display the requests that have been sent to this endpoint.

        Args:
            rowIndex: the row that was clicked.
        """
        endpoint = self.getEndpoint(rowIndex)
        self.state.requestTableModel.updateRequests(endpoint.requests)
        self.state.requestTableModel.selectRow(0)

    def update(self, requestModel, httpRequestResponse):
        """
        Allows for new data to be stored regarding our already stored requests. They are persisted to disk for reduced RAM usage.

        In particular, this method is called when requests are repeated, and new information is stored regarding those responses, such as the status code or the response length.

        It is safe to call this method from multiple threads because it implements a lock.

        Args:
            requestModel: the RequestModel that was modified. Because of python internals, this is a pointer to the same object present in self.endpoints[x].request, and can therefore be modified directly.
            httpRequestResponse: the HttpRequestResponse object returned by performing the new request.
        """
        with self.lock:

            if not httpRequestResponse.response:
                msg = "No response received on update call() for %s. Is the server now offline?" % (requestModel.analyzedRequest.url)
                log(msg)
                raise NoResponseException(msg)

            httpRequestResponse = self.callbacks.saveBuffersToTempFiles(httpRequestResponse)

            requestModel.repeatedHttpRequestResponse = httpRequestResponse
            requestModel.repeatedAnalyzedResponse = self.callbacks.helpers.analyzeResponse(httpRequestResponse.response)
            requestModel.repeatedAnalyzedRequest = self.callbacks.helpers.analyzeRequest(httpRequestResponse.request)
            requestModel.repeated = True

            self.fireTableDataChanged()

    def setFuzzed(self, endpointModel, fuzzed):
        """
        Thread safe way to mark EndpointModel as fuzzed. This is done here as opposed to in the model to make easy use of the `self.lock` variable.

        Args:
            endpointModel: the EndpointModel object.
            fuzzed: new fuzzed value.
        """
        with self.lock:
            endpointModel.fuzzed = fuzzed
            store = "true" if fuzzed else "false"

            hash = self.generateEndpointHash(endpointModel.requests[0].analyzedRequest)[0]
            self.fuzzedMetadata[hash] = fuzzed
            self.callbacks.saveExtensionSetting("fuzzed-metadata", json.dumps(self.fuzzedMetadata))

            self.fireTableDataChanged()

class RequestTableModel(AbstractTableModel):
    """
    Table model for the requests panel on the Results tab on the right.
    """

    cols = ["URL", "Orig Status", "Status", "Orig Len", "Resp Len", "Diff"]

    def __init__(self, state, callbacks):
        """
        Initialization function.

        Args:
            state: the general state object.
            callbacks: burp callbacks
        """
        self.requests = []
        self.lock = Lock()
        self.state = state
        self.callbacks = callbacks

    def getRowCount(self):
        """
        Returns the number of elements in this table.
        """
        try:
            return len(self.requests)
        except:
            return 0

    def getColumnCount(self):
        """
        Returns the number of columns in this table.
        """
        return len(self.cols)

    def getColumnName(self, columnIndex):
        """
        Gets the name for the column at this particular position.

        Args:
            columnIndex: the index to fetch the column name for.
        """
        return self.cols[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        """
        Returns the corresponding value for the request at the position specified by the parameters.

        Args:
            rowIndex: y value to return the value for.
            columnIndex: x value to return the value for.
        """

        request = self.requests[rowIndex]
        if columnIndex == 0:
            url = request.analyzedRequest.url
            queryString = url.query
            if queryString:
                return url.path + "?" + queryString
            else:
                return url.path
        elif columnIndex == 1:
            if request.analyzedResponse:
                return request.analyzedResponse.statusCode
            else:
                return ""
        elif columnIndex == 2:
            if request.repeatedAnalyzedResponse:
                return request.repeatedAnalyzedResponse.statusCode
            else:
                return ""
        elif columnIndex == 3:
            if request.httpRequestResponse.response:
                return len(request.httpRequestResponse.response)
            else:
                return ""
        elif columnIndex == 4:
            if request.repeatedAnalyzedResponse:
                return len(request.repeatedHttpRequestResponse.response)
            else:
                return ""
        elif columnIndex == 5:
            if request.repeatedAnalyzedResponse:
                return abs(len(request.httpRequestResponse.response) - len(request.repeatedHttpRequestResponse.response))
            else:
                return ""

    def updateRequests(self, requests):
        """
        Replaces the requests we are currently displaying with a new set of requests.

        Gets fired when a user clicks on the endpoint table.

        Args:
            requests: an array of requests to replace the current requests with.
        """
        with self.lock:
            nb_requests = len(requests)
            self.requests = requests
            self.fireTableRowsInserted(0, nb_requests - 1)

    def selectRow(self, rowIndex):
        """
        Gets called when a hacker clicks on a request in the top-right panel on the results page.

        Args:
            rowIndex: the row number that was clicked.
        """
        request = self.requests[rowIndex]

        self.state.originalRequestViewer.setMessage(request.httpRequestResponse.request, False)
        self.state.originalResponseViewer.setMessage(request.httpRequestResponse.response, False)
        self.state.originalHttpRequestResponse = request.httpRequestResponse

        if request.repeatedHttpRequestResponse:
            self.state.repeatedRequestViewer.setMessage(request.repeatedHttpRequestResponse.request, False)
            self.state.repeatedResponseViewer.setMessage(request.repeatedHttpRequestResponse.response, False)
            self.state.repeatedHttpRequestResponse = request.repeatedHttpRequestResponse
        else:
            self.state.repeatedRequestViewer.setMessage(String("").getBytes(), False)
            self.state.repeatedResponseViewer.setMessage(String("").getBytes(), False)
            self.state.repeatedHttpRequestResponse = None


class ReplacementRuleTableModel(AbstractTableModel):

    cols = ["#", "Rule type", "Search", "Replace"]

    def __init__(self):
        """
        Model for storing the replacement rules.

        Replacement rules are rules that are applied prior to resending any request and can perform tasks such as replacing a header's value with another's value or replacing a string in the request body.
        """
        self.lock = Lock()
        self.rules = []
        self.id_counter = 0
        self.selected = None

    def getRowCount(self):
        """
        Returns the number of rows for rendering the table.
        """
        try:
            return len(self.rules)
        except:
            return 0

    def getColumnCount(self):
        """
        Returns the number of columns for rendering the table.
        """
        return len(self.cols)

    def getColumnName(self, columnIndex):
        """
        Returns the number of columns for rendering the table header.
        """
        return self.cols[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        """
        Returns the value for a cell at specific coordinates.

        Args:
            rowIndex: which row to fetch the value for.
            columnIndex: which column to fetch the value for.
        """
        rule = self.rules[rowIndex]
        if columnIndex == 0:
            return rule.id
        if columnIndex == 1:
            return rule.type
        if columnIndex == 2:
            return rule.search
        if columnIndex == 3:
            return rule.replacement
        return ""

    def add(self, type, search, replacement):
        """
        Adds a replacement rule. Called when a hacker clicks the "Add" button on the Config panel.

        Args:
            type: which kind of rule to apply.
            search: search value, e.g. header name or string to replace.
            replacement: replacement value.
        """
        with self.lock:
            self.id_counter += 1
            self.rules.append(ReplacementRuleModel(self.id_counter, type, search, replacement))

            rows = len(self.rules) - 1
            self.fireTableRowsInserted(rows, rows)

    def edit(self, id, type, search, replacement):
        """
        Edits a replacement rule. Called when a hacker clicks the "Edit" button and a row is selected in the config panel.

        Args:
            id: the internal id of the rule to replace. See ReplacementRuleModel.id
            type: which kind of rule to apply.
            search: search value.
            replace: replacement value.
        """
        with self.lock:
            for nb, rule in enumerate(self.rules):
                if rule.id == id:
                    self.rules[nb].type = type
                    self.rules[nb].search = search
                    self.rules[nb].replacement = replacement

                    self.fireTableDataChanged()

    def delete(self, id):
        """
        Deletes a replacement rule. Called when a hacker clicks "Delete" in the config panel.

        Args:
            id: the internal id of the rule to delete.
        """
        with self.lock:
            for nb, rule in enumerate(self.rules):
                if rule.id == id:
                    del self.rules[nb]

                    self.fireTableDataChanged()

    def selectRow(self, rowIndex):
        """
        Gets called when a user selects a row. This is useful for "Edit" or "Delete" operations.
        """
        self.selected = self.rules[rowIndex]

    def exportJsonRules(self):
        """
        Returns current rules as JSON to persist as a burp setting.
        """
        simple = []
        for element in self.rules:
            simple.append(dict(element.__dict__))

        return json.dumps(simple)

    def importJsonRules(self, jsonRules):
        """
        Overwrites the current rules with the json string.

        Args:
            jsonRules: a json string as exported by self.exportJsonRules().
        """
        jsonObject = json.loads(jsonRules)
        rules = []
        for element in jsonObject:
            self.id_counter += 1
            rules.append(ReplacementRuleModel(self.id_counter, element['type'], element['search'], element['replacement']))

        with self.lock:
            self.rules = rules
            self.fireTableDataChanged()
