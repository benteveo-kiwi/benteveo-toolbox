import math
import unittest
import operator
from collections import OrderedDict
from java.awt import Component
from benteveo_toolbox import BurpExtender
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel
from models import EndpointModel, RequestModel, ReplacementRuleModel
from ui import ToolboxCallbacks
from java.net import URL
from java.util import ArrayList
from java.lang import String
import ui
import utility
import contextlib

class GenericMock(object):
    """
    A generic mocking class that accepts calls to any method without crashing.

    Because we're using jython, installing commonly used mocking frameworks takes more than one command and could make creating a testing environment more complicated.
    """

    call_count = 0

    def __init__(self):
        self.mocked = {}

    def __getattr__(self, name):
        """
        Gets called when an attribute is retrieved.

        It attempts to retrieve the value from within the object if it exists, and if not returns another instance of GenericMock. If the same attribute is retrieved more than once, the same instance of GenericMock is retrieved.

        Args:
            name: the name of the attribute being retrieved.
        """
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            pass

        try:
            return self.mocked[name]
        except KeyError:
            self.mocked[name] = GenericMock()
            return self.mocked[name]

    def __call__(self, *args):
        """
        This method is called when the object is invoked as a function.

        It records the number of times it was called as well as the arguments it was called with the last time. It returns the `return_value` property so that users of this api can mock the return value of the function.
        """
        self.call_count += 1
        self.call_args = args
        return self.return_value

    def getComponent(self, *args):
        """
        This is a hard-coded method that is required because of java type issues. It is required in many tests so it's less repetitive to put it here.
        """
        class ComponentMock(Component):
            pass

        return ComponentMock()

    def loadExtensionSetting(self, *args):
        """
        This is a hard-coded method that is required because of java type issues. It is required in many tests so it's less repetitive to put it here.
        """
        return "setting"

    def __len__(self):
        """
        This function is called when len() is called on GenericMock(). For ease of testability it always returns 1337.
        """
        return 1337



class TestToolbox(unittest.TestCase):
    """
    Main testing class. Contains tests for all classes within the codebase.
    """
    @contextlib.contextmanager
    def mockSwingClasses(_):
        """
        Mocks JOptionPane so that a pop-up window does not appear during test runs.

        The annotation makes it compatible with the `with` statement. See https://stackoverflow.com/a/3774934 for more info.
        """
        _JOptionPane = ui.JOptionPane
        _JTextField = ui.JTextField
        _Box = ui.Box

        ui.JOptionPane = GenericMock()
        ui.JOptionPane.showConfirmDialog.return_value = _JOptionPane.OK_OPTION
        ui.JOptionPane.OK_OPTION = _JOptionPane.OK_OPTION

        ui.JTextField = GenericMock()
        ui.Box = GenericMock()
        yield
        ui.JOptionPane = _JOptionPane
        ui.JTextField = _JTextField
        ui.Box = _Box

    @contextlib.contextmanager
    def mockUtilityCalls(_):
        """
        Mocks calls to the utility module for ease of testability.
        """
        perform_request = ui.perform_request
        apply_rules = ui.apply_rules
        get_header = ui.get_header

        ui.perform_request = GenericMock()
        ui.apply_rules = GenericMock()
        ui.get_header = GenericMock()

        yield

        ui.perform_request = perform_request
        ui.apply_rules = apply_rules
        ui.get_header = get_header

    def _cem(self, method, url, dict=None):
        """
        Creates EndpointModel convenience function.

        Returns a OrderedDict with the added endpoint module. Optionally, you may pass a dict that will be added to and then returned.

        Args:
            method: a method, e.g. "GET"
            url: a url, e.g. "http://www.example.org/"
            dict: a dict. If set that dict will be inserted into instead of a new one created.
        """

        if not dict:
            dict = OrderedDict()

        httpRequestResponse = GenericMock()

        callbacks = GenericMock()
        callbacks.helpers.analyzeRequest.return_value.method = method
        callbacks.helpers.analyzeRequest.return_value.url = URL(url)
        callbacks.helpers.analyzeResponse.return_value.statusCode = 200

        request = RequestModel(httpRequestResponse, callbacks)

        hash = method + "|" + url.split("?")[0]

        if not hash in dict:
            dict[hash] = EndpointModel(method, url)
        dict[hash].add(request)

        return dict

    def _cetm(self):
        """
        Create EndpointTableModel convenience function
        """
        state = GenericMock()
        callbacks = GenericMock()
        etm = EndpointTableModel(state, callbacks)

        return etm, state, callbacks

    def _crtm(self):
        """
        Create RequestTableModel convenience function.
        """
        state = GenericMock()
        callbacks = GenericMock()
        rtm = RequestTableModel(state, callbacks)

        return rtm, state, callbacks

    def _ctc(self):
        """
        Create ToolBoxCallbacks convenience method.
        """
        state = GenericMock()
        burpCallbacks = GenericMock()
        cb = ToolboxCallbacks(state, burpCallbacks)

        return cb, state, burpCallbacks

    def _crrtm(self):
        """
        Create ReplacementRuleTableModel convenience method.
        """
        return ReplacementRuleTableModel()

    def testCanRunMainWithoutCrashing(self):
        be = BurpExtender()
        mock = GenericMock()
        be.registerExtenderCallbacks(mock)

        self.assertEqual(mock.setExtensionName.call_count, 1)

    def testGenerateEndpointHash(self):
        etm, state, callbacks = self._cetm()


        mockRequestInfo = GenericMock()
        mockRequestInfo.method = "GET"
        mockRequestInfo.url = URL("http://www.example.org/users")
        mockRequestInfo.status = "200"

        hash, _, _ = etm.generateEndpointHash(mockRequestInfo)

        self.assertEquals(hash, "GET|http://www.example.org/users")

    def testGenerateEndpointHash64ByteHexadecimal(self):
        etm, state, callbacks = self._cetm()

        mockRequestInfo = GenericMock()
        mockRequestInfo.method = "GET"
        mockRequestInfo.url = URL("http://www.example.org/users/748bbea58bb5db34e95d02edb2935c0f25cb1593e5ab837767e260a349c02ca7")
        mockRequestInfo.status = "200"

        hash, _, _ = etm.generateEndpointHash(mockRequestInfo)

        self.assertEquals(hash, "GET|http://www.example.org/users/{ID}")

    def testRefreshPersistsSettings(self):
        cb, state, burpCallbacks = self._ctc()

        state.scopeTextArea.getText.return_value = "https://example.com/\nhttps://example.org/\n"
        burpCallbacks.getSiteMap.return_value = [GenericMock(),GenericMock(),GenericMock()]

        cb.refreshButtonClicked(GenericMock())

        self.assertEquals(state.scopeTextArea.getText.call_count, 1)
        self.assertEquals(burpCallbacks.saveExtensionSetting.call_count, 1)
        self.assertEquals(burpCallbacks.getSiteMap.call_count, 2)
        self.assertEquals(state.endpointTableModel.clear.call_count, 1)
        self.assertEquals(state.endpointTableModel.add.call_count, 6)

    def testAddEndpointTableModelSimple(self):
        state = GenericMock()
        callbacks = GenericMock()
        etm = EndpointTableModel(state, callbacks)

        ret = callbacks.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = URL("http://www.example.org/users")

        etm.add(GenericMock())

        self.assertEqual(len(etm.endpoints), 1)
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].url, "http://www.example.org/users")
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].method, "GET")

    def testAddEndpointTableModelWithQueryString(self):
        etm, state, callbacks = self._cetm()

        ret = callbacks.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = URL("http://www.example.org/users?count=50")

        etm.add(GenericMock())

        self.assertEqual(len(etm.endpoints), 1)
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].url, "http://www.example.org/users")
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].method, "GET")

    def testClearEndpointTableModel(self):
        etm, state, callbacks = self._cetm()

        etm.fireTableRowsDeleted = GenericMock()

        ret = callbacks.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = URL("http://www.example.org/users?count=50")

        etm.add(GenericMock())
        etm.clear()

        self.assertEqual(len(etm.endpoints), 0)
        self.assertEqual(etm.fireTableRowsDeleted.call_count, 1)

    def testClearWhenEmpty(self):
        etm, state, callbacks = self._cetm()

        etm.fireTableRowsDeleted = GenericMock()

        etm.clear()

        self.assertEqual(etm.fireTableRowsDeleted.call_count, 0)

    def testEndpointTableModelGetValueAt(self):
        etm, state, callbacks = self._cetm()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/profiles", dict)
        etm.endpoints = dict

        self.assertEquals(etm.getValueAt(0, 0), "GET")
        self.assertEquals(etm.getValueAt(0, 1), "http://www.example.org/users")

        self.assertEquals(etm.getValueAt(1, 0), "GET")
        self.assertEquals(etm.getValueAt(1, 1), "http://www.example.org/profiles")
        self.assertEquals(etm.getValueAt(1, 2), 1)
        self.assertEquals(etm.getValueAt(1, 3), 0)
        self.assertEquals(etm.getValueAt(1, 4), 0)

    def testTableCallsModel(self):
        etm, state, callbacks = self._cetm()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/users", dict)
        etm.endpoints = dict

        etm.selectRow(0)

        self.assertEquals(state.requestTableModel.updateRequests.call_count, 1)
        self.assertEquals(len(state.requestTableModel.updateRequests.call_args[0]), 2)

    def testRequestsTableModelUpdateMethod(self):
        rtm, state, callback = self._crtm()

        rtm.fireTableRowsInserted = GenericMock()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/users", dict)

        rtm.updateRequests(dict["GET|http://www.example.org/users"].requests)

        self.assertEquals(len(rtm.requests), 2)
        self.assertEquals(rtm.fireTableRowsInserted.call_count, 1)
        self.assertEquals(rtm.fireTableRowsInserted.call_args, (0, 1))

    def testRequestsTableModelGetValueAt(self):
        rtm, state, callback = self._crtm()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/users?userId=300", dict)
        rtm.requests = dict["GET|http://www.example.org/users"].requests

        self.assertEquals(rtm.getValueAt(0, 0), "/users")
        self.assertEquals(rtm.getValueAt(0, 1), 200)
        self.assertEquals(rtm.getValueAt(0, 2), "")
        self.assertEquals(rtm.getValueAt(0, 3), 1337)
        self.assertEquals(rtm.getValueAt(0, 4), "")
        self.assertEquals(rtm.getValueAt(0, 4), "")

        self.assertEquals(rtm.getValueAt(1, 0), "/users?userId=300")

    def testRequestsTableModelSelectRow(self):
        rtm, state, callback = self._crtm()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/users?userId=300", dict)
        rtm.requests = dict["GET|http://www.example.org/users"].requests

        rtm.selectRow(0)

        self.assertEquals(state.requestViewer.setMessage.call_count, 1)
        self.assertEquals(state.responseViewer.setMessage.call_count, 1)
        self.assertEquals(state.currentlyDisplayedItem, rtm.requests[0].httpRequestResponse)

    def testReplacementRules(self):
        rrtm = self._crrtm()
        rrtm.add("type", "search", "replace")
        rrtm.add("type2", "search2", "replace2")

        self.assertEquals(rrtm.getRowCount(), 2)
        self.assertEquals(rrtm.getValueAt(0, 0), 1)
        self.assertEquals(rrtm.getValueAt(0, 1), "type")
        self.assertEquals(rrtm.getValueAt(0, 2), "search")
        self.assertEquals(rrtm.getValueAt(0, 3), "replace")
        self.assertEquals(rrtm.getValueAt(1, 0), 2)
        self.assertEquals(rrtm.getValueAt(1, 1), "type2")
        self.assertEquals(rrtm.getValueAt(1, 2), "search2")
        self.assertEquals(rrtm.getValueAt(1, 3), "replace2")

        rrtm.edit(2, "typemodified", "searchmodified", "replacemodified")
        self.assertEquals(rrtm.getValueAt(1, 0), 2)
        self.assertEquals(rrtm.getValueAt(1, 1), "typemodified")
        self.assertEquals(rrtm.getValueAt(1, 2), "searchmodified")
        self.assertEquals(rrtm.getValueAt(1, 3), "replacemodified")

        rrtm.delete(2)
        self.assertEquals(rrtm.getRowCount(), 1)

    def testAddButton(self):
        with self.mockSwingClasses():
            cb, state, burpCallbacks = self._ctc()

            state.replacementRuleTableModel.rules = [ReplacementRuleModel(1, "type", "search", "replacement")]

            ui.JTextField.return_value.text = ""
            cb.addButtonClicked(GenericMock())
            self.assertEquals(state.replacementRuleTableModel.add.call_count, 0, "Should be 0 because input is empty.")

            ui.JTextField.return_value.text = "valid"
            cb.addButtonClicked(GenericMock())

            self.assertEquals(state.replacementRuleTableModel.add.call_count, 1, "Should have saved user input.")
            self.assertEquals(burpCallbacks.saveExtensionSetting.call_count, 1)

    def testReplacementRulesJson(self):
        rrtm = self._crrtm()
        rrtm.add("type", "search", "replace")
        rrtm.add("type2", "search2", "replace2")

        self.assertEquals(rrtm.exportJsonRules(), '[{"type": "type", "search": "search", "id": 1, "replacement": "replace"}, {"type": "type2", "search": "search2", "id": 2, "replacement": "replace2"}]')

    def testReplacementRulesJsonImport(self):
        rrtm = self._crrtm()

        json ='[{"type": "type", "search": "search", "id": 1, "replacement": "replace"}, {"type": "type2", "search": "search2", "id": 2, "replacement": "replace2"}]'

        rrtm.fireTableDataChanged = GenericMock()
        rrtm.importJsonRules(json)

        self.assertEquals(rrtm.getRowCount(), 2)
        self.assertEquals(rrtm.getValueAt(0, 0), 1)
        self.assertEquals(rrtm.getValueAt(0, 1), "type")
        self.assertEquals(rrtm.getValueAt(0, 2), "search")
        self.assertEquals(rrtm.getValueAt(0, 3), "replace")
        self.assertEquals(rrtm.getValueAt(1, 0), 2)
        self.assertEquals(rrtm.getValueAt(1, 1), "type2")
        self.assertEquals(rrtm.getValueAt(1, 2), "search2")
        self.assertEquals(rrtm.getValueAt(1, 3), "replace2")
        self.assertEquals(rrtm.fireTableDataChanged.call_count, 1)

    def testCheckButtonPersistsState(self):
        cb, state, burpCallbacks = self._ctc()

        cb.checkButtonClicked(GenericMock())

        self.assertEquals(burpCallbacks.saveExtensionSetting.call_count, 1)

    def testCheckButtonCallsPerformRequestWithRightParams(self):

        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()
            cb.checkButtonClicked(GenericMock())

            self.assertEquals(ui.apply_rules.call_count, 1)
            self.assertEquals(ui.perform_request.call_count, 1)
            self.assertEquals(ui.get_header.call_count, 1)

    def testGetHeader(self):
        testRequest = "whatever"
        callbacks = GenericMock()

        headers = ArrayList()
        headers.add("GET / HTTP/1.1")
        headers.add("Host: example.org")

        callbacks.helpers.analyzeRequest.return_value.headers = headers

        host_header = utility.get_header(callbacks, testRequest, "host")

        self.assertEquals("example.org", host_header)

    def testApplyRulesSubstituteHeader(self):
        rrtm = self._crrtm()
        rrtm.add(utility.REPLACE_HEADER_NAME, "X-test-header", "newvalue")

        bytes = String("wuh eva").getBytes()

        headers = ArrayList()
        headers.add("GET / HTTP/1.1")
        headers.add("Host: example.org")
        headers.add("X-test-header: oldvalue")

        callbacks = GenericMock()
        utility.Arrays = GenericMock()
        callbacks.helpers.analyzeRequest.return_value.headers = headers

        modified, _ = utility.apply_rules(callbacks, rrtm.rules, bytes)
        newHeaders = callbacks.helpers.buildHttpMessage.call_args[0]

        self.assertEquals(modified, 1)
        self.assertTrue("X-test-header: newvalue" in newHeaders, "Should contain new replaced header.")

if __name__ == '__main__':
    unittest.main()
