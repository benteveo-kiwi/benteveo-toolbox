from benteveo_toolbox import BurpExtender
from burp import IBurpExtenderCallbacks, IExtensionHelpers, IScannerInsertionPoint
from collections import OrderedDict
from implementations import ScannerInsertionPoint
from java.awt import Component
from java.lang import String, IllegalArgumentException, UnsupportedOperationException, Class
from java.net import URL
from java.util import ArrayList
from models import EndpointModel, RequestModel, ReplacementRuleModel
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel
from ui import ToolboxCallbacks, STATUS_OK, STATUS_FAILED
import contextlib
import math
import operator
import ui
import unittest
import utility

utility.INSIDE_UNIT_TEST = True

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

        It records the number of times it was called as well as the arguments it was called with the last time. It returns the `return_value` property so that users of this api can mock the return value of the function. If `raise` is an exception on this object, we raise that value.
        """

        if type(self.raise) == Exception or type(self.raise) == Class:
            raise self.raise

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

    def __iter__(self):
        """
        This function is called when a caller attempts to use generic mock as an iterator. It yields three GenericMock() objects.
        """
        yield GenericMock()
        yield GenericMock()
        yield GenericMock()

    def __getitem__(self, item):
        """
        Makes object subscriptable, e.g. genericMockInstance['test']
        """
        return GenericMock()


class TestException(Exception):
    """
    Custom exception for testing.
    """
    pass

def raise_exception(*args, **kwargs):
    """
    Convenience function for raising an exception
    """
    raise TestException()

class TestToolbox(unittest.TestCase):
    """
    Main testing class. Contains tests for all classes within the codebase.
    """
    @contextlib.contextmanager
    def mockSwingClasses(_):
        """
        Mocks JOptionPane so that a pop-up window does not appear during test runs.  Note that it only gets mocked in the "ui.py" file.

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
        Mocks calls to the utility module for ease of testability. Note that it only gets mocked in the "ui.py" file.
        """
        apply_rules = ui.apply_rules
        get_header = ui.get_header
        log = ui.log
        sendMessageToSlack = ui.sendMessageToSlack

        ui.apply_rules = GenericMock()
        ui.get_header = GenericMock()
        ui.log = GenericMock()
        ui.sendMessageToSlack = GenericMock()

        ui.apply_rules.return_value = (False, None)

        yield

        ui.apply_rules = apply_rules
        ui.get_header = get_header
        ui.log = log
        ui.sendMessageToSlack = sendMessageToSlack

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

    def _cetm_populate(self):
        """
        Create EndpointTableModel convenience function. Also populates the endpoints.
        """
        etm, state, callbacks = self._cetm()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/users", dict)
        etm.endpoints = dict

        endpointModel = etm.endpoints["GET|http://www.example.org/users"]

        return etm, state, callbacks, endpointModel

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

        state.sessionCheckTextarea.text = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
        state.executorService = GenericMock()

        request = ArrayList()
        request.add("GET / HTTP/1.1")
        request.add("Host: example.org")
        burpCallbacks.helpers.analyzeRequest.return_value.headers = request

        cb = ToolboxCallbacks(state, burpCallbacks)
        cb.sleep = GenericMock()

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

        state.scopeTextArea.text = "https://example.com/\nhttps://example.org/\n"
        burpCallbacks.getSiteMap.return_value = [GenericMock(),GenericMock(),GenericMock()]

        cb.refreshButtonClicked(GenericMock())

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

    def testAddEndpointTableModelMax100(self):
        state = GenericMock()
        callbacks = GenericMock()
        etm = EndpointTableModel(state, callbacks)

        ret = callbacks.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = URL("http://www.example.org/users")

        for a in range(200):
            etm.add(GenericMock())

        self.assertEqual(len(etm.endpoints), 1)
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].url, "http://www.example.org/users")
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].method, "GET")
        self.assertEqual(len(etm.endpoints["GET|http://www.example.org/users"].requests), etm.maxRequests)

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

        etm.endpoints["GET|http://www.example.org/users"].requests[0].httpRequestResponse.request = String("748bbea58bb5db34e95d02edb2935c0f25cb1593e5ab837767e260a349c02ca7").getBytes()
        etm.endpoints["GET|http://www.example.org/profiles"].requests[0].httpRequestResponse.request = String("lala").getBytes()

        etm.endpoints["GET|http://www.example.org/users"].fuzzed = True
        etm.endpoints["GET|http://www.example.org/profiles"].fuzzed = False

        self.assertEquals(etm.getValueAt(0, 0), "GET")
        self.assertEquals(etm.getValueAt(0, 1), "http://www.example.org/users")
        self.assertEquals(etm.getValueAt(0, 5), True)
        self.assertEquals(etm.getValueAt(0, 6), True)


        self.assertEquals(etm.getValueAt(1, 0), "GET")
        self.assertEquals(etm.getValueAt(1, 1), "http://www.example.org/profiles")
        self.assertEquals(etm.getValueAt(1, 2), 1)
        self.assertEquals(etm.getValueAt(1, 3), 0)
        self.assertEquals(etm.getValueAt(1, 4), 0)

        self.assertEquals(etm.getValueAt(1, 5), False)
        self.assertEquals(etm.getValueAt(1, 6), False)


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

        rtm.requests[1].repeatedHttpRequestResponse = GenericMock()
        rtm.requests[1].repeatedAnalyzedResponse = GenericMock()

        self.assertEquals(rtm.getValueAt(0, 0), "/users")
        self.assertEquals(rtm.getValueAt(0, 1), 200)
        self.assertEquals(rtm.getValueAt(0, 2), "")
        self.assertEquals(rtm.getValueAt(0, 3), 1337)
        self.assertEquals(rtm.getValueAt(0, 4), "")
        self.assertEquals(rtm.getValueAt(0, 4), "")

        self.assertEquals(rtm.getValueAt(1, 0), "/users?userId=300")
        self.assertEquals(rtm.getValueAt(1, 2), rtm.requests[1].repeatedAnalyzedResponse.statusCode)
        self.assertEquals(rtm.getValueAt(1, 4), 1337)
        self.assertEquals(rtm.getValueAt(1, 5), 0)

    def testRequestsTableModelSelectRow(self):
        rtm, state, callback = self._crtm()

        dict = self._cem("GET", "http://www.example.org/users")
        dict = self._cem("GET", "http://www.example.org/users?userId=300", dict)
        rtm.requests = dict["GET|http://www.example.org/users"].requests

        rtm.selectRow(0)

        self.assertEquals(state.originalRequestViewer.setMessage.call_count, 1)
        self.assertEquals(state.originalResponseViewer.setMessage.call_count, 1)
        self.assertEquals(state.originalHttpRequestResponse, rtm.requests[0].httpRequestResponse)
        self.assertEquals(state.repeatedHttpRequestResponse, rtm.requests[0].repeatedHttpRequestResponse)

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

        with self.mockSwingClasses():
            with self.mockUtilityCalls():

                cb.checkButtonClicked(GenericMock())

                self.assertEquals(burpCallbacks.saveExtensionSetting.call_count, 1)

    def testCheckButtonBasicCalls(self):

        with self.mockSwingClasses():
            with self.mockUtilityCalls():
                cb, state, burpCallbacks = self._ctc()
                cb.checkButtonClicked(GenericMock())

                self.assertEquals(ui.apply_rules.call_count, 1)
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

    def testRunAllButtonInvalidState(self):
        with self.mockSwingClasses():
            with self.mockUtilityCalls():
                cb, state, burpCallbacks = self._ctc()
                state.status = STATUS_FAILED
                cb.resendAllButtonClicked(GenericMock())

                self.assertEquals(ui.JOptionPane.showMessageDialog.call_count, 1)

    def testRunAllButtonValidState(self):
        with self.mockSwingClasses():
            with self.mockUtilityCalls():
                cb, state, burpCallbacks = self._ctc()
                state.status = STATUS_OK

                etm, _, _, endpointModel = self._cetm_populate()
                state.endpointTableModel = etm

                cb.resendAllButtonClicked(GenericMock())

                self.assertEquals(state.executorService.submit.call_count, 2)

    def testResendRequestModel(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()
            etm, _, _, endpointModel = self._cetm_populate()

            state.endpointTableModel = etm
            state.endpointTableModel.update = GenericMock()
            ui.apply_rules.return_value = (1, bytearray("lel"))

            cb.resendRequestModel(endpointModel.requests[0])

            self.assertEquals(burpCallbacks.makeHttpRequest.call_count, 1)
            self.assertEquals(state.endpointTableModel.update.call_count, 1)

    def testResendRequestModelLogoutURL(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            request = GenericMock()
            request.analyzedRequest.url.path = "/logout"

            cb.resendRequestModel(request)

            self.assertEquals(burpCallbacks.makeHttpRequest.call_count, 0)
            self.assertEquals(state.endpointTableModel.update.call_count, 0)
            self.assertEquals(ui.log.call_count, 1)

    def testEndpointTableModelUpdate(self):
        etm, state, callbacks, endpointModel = self._cetm_populate()

        requestModel = GenericMock()
        newResponse = GenericMock()
        etm.update(requestModel, newResponse)

        self.assertEquals(requestModel.repeatedHttpRequestResponse, newResponse)
        self.assertEquals(requestModel.repeated, True)
        self.assertEquals(requestModel.repeatedAnalyzedResponse, callbacks.helpers.analyzeResponse.return_value)

    def testSameStatusPercentage(self):
        em = EndpointModel("GET", "/lol")

        requestA = GenericMock()
        requestB = GenericMock()

        em.requests = [requestA, requestB]

        requestA.repeatedAnalyzedResponse.statusCode = 200
        requestA.analyzedResponse.statusCode = 200

        requestB.repeatedAnalyzedResponse.statusCode = 200
        requestB.analyzedResponse.statusCode = 403

        self.assertEquals(em.percentSameStatus, 50)

        requestB.repeatedAnalyzedResponse.statusCode = 200
        requestB.analyzedResponse.statusCode = 200

        self.assertEquals(em.percentSameStatus, 100)

    def testContainsId(self):
        em = EndpointModel("GET", "/lol")

        requestA = GenericMock()
        requestA.httpRequestResponse.request = String("qwfqwfqwfq 748bbea58bb5db34e95d02edb2935c0f25cb1593e5ab837767e260a349c02ca7").getBytes()
        requestB = GenericMock()
        requestB.httpRequestResponse.request = String("qgwgqwgwgqw").getBytes()

        em.requests = [requestA, requestB]

        self.assertTrue(em.containsId)

    def testClickFuzzOnlyIfSameStatusDifferent(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            state.executorService = GenericMock()

            em = GenericMock()
            em.fuzzed = False

            requestA = GenericMock()
            requestB = GenericMock()

            em.requests = [requestA, requestB]
            state.endpointTableModel.endpoints = {"GET|/lol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 403

            requestB.analyzedResponse.statusCode = 200
            requestB.repeatedAnalyzedResponse.statusCode = 403

            cb.fuzzButtonClicked(GenericMock())

            self.assertEquals(state.executorService.submit.call_count, 0)

    def testClickFuzzRepeats(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = False

            requestA = GenericMock()

            em.requests = [requestA]
            state.endpointTableModel.endpoints = {"GET|/lol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse = None

            cb.resendRequestModel = GenericMock()
            try:
                cb.fuzzButtonClicked(GenericMock())
            except AttributeError:
                pass

            self.assertEquals(cb.resendRequestModel.call_count, 2)

    def testClickFuzzMaxConcurrentRequests(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = False

            state.perRequestExecutorService.submit.return_value.isDone = raise_exception

            requestA = GenericMock()

            em.requests = [requestA]
            state.endpointTableModel.endpoints = {"GET|/l.ol": em,"GET|/lo<<l": em,"GET|/loOOl": em,"GET|/lJJol": em,"GET|/ZZZol": em,"GET|/loXXXl": em,"GET|/lasasCol": em,"GET|/lol1221": em,"GET|/lolASAS": em,"GET|/lddddol": em,"GET|/lolsss": em,"GET|/aaalol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 200

            try:
                cb.fuzzButtonClicked(GenericMock())
            except TestException:
                pass

            self.assertEquals(state.perRequestExecutorService.submit.call_count, cb.maxConcurrentRequests)

    def testClickFuzzMaxConcurrentRequestsOneMore(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = False


            utility.nb_calls = 0
            def return_true_once(*args, **kwargs):
                if utility.nb_calls == 0:
                    utility.nb_calls +=1
                    return True
                else:
                    raise TestException()

            state.perRequestExecutorService.submit.return_value.isDone = return_true_once

            requestA = GenericMock()

            em.requests = [requestA]
            state.endpointTableModel.endpoints = {"GET|/l.ol": em,"GET|/lo<<l": em,"GET|/loOOl": em,"GET|/lJJol": em,"GET|/ZZZol": em,"GET|/loXXXl": em,"GET|/lasasCol": em,"GET|/lol1221": em,"GET|/lolASAS": em,"GET|/lddddol": em,"GET|/lolsss": em,"GET|/aaalol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 200

            try:
                cb.fuzzButtonClicked(GenericMock())
            except TestException:
                pass

            self.assertEquals(state.perRequestExecutorService.submit.call_count, cb.maxConcurrentRequests + 1)

    def testClickFuzzOnlyIfSameStatusSame(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = False

            requestA = GenericMock()
            requestB = GenericMock()

            em.requests = [requestA, requestB]
            state.endpointTableModel.endpoints = {"GET|/lol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 403

            requestB.analyzedResponse.statusCode = 200
            requestB.repeatedAnalyzedResponse.statusCode = 200

            cb.fuzzButtonClicked(GenericMock())

            self.assertEquals(state.perRequestExecutorService.submit.call_count, 1)

    def testFuzzRequestModel(self):
        cb, state, burpCallbacks = self._ctc()
        ui.FastScan = GenericMock()
        cb.fuzzRequestModel(GenericMock())

        self.assertEquals(ui.FastScan.call_count, 1)
        self.assertEquals(state.executorService.submit.call_count, 3)

        state.executorService.submit.return_value.isDone = raise_exception

        classIsDone = False
        try:
            cb.fuzzRequestModel(GenericMock())
        except TestException:
            classIsDone = True

        self.assertTrue(classIsDone, "Calls is done.")

    def testPersistsMetadata(self):
        etm, state, callbacks = self._cetm()
        em = GenericMock()
        etm.generateEndpointHash = GenericMock()
        etm.generateEndpointHash.return_value = "uniqueid"

        etm.setFuzzed(em, True)

        self.assertEquals(callbacks.saveExtensionSetting.call_count, 1)

    def testPersistsMetadataLoad(self):
        state = GenericMock()
        callbacks = GenericMock()
        callbacks.loadExtensionSetting = GenericMock()
        callbacks.loadExtensionSetting.return_value = "true"
        etm = EndpointTableModel(state, callbacks)

        ret = callbacks.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = URL("http://www.example.org/users")

        etm.add(GenericMock())

        self.assertEqual(callbacks.loadExtensionSetting.call_count, 1)
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].fuzzed, True)

    def testFuzzOnlyIfNotFuzzedAlready(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = True
            requestA = GenericMock()

            em.requests = [requestA]
            state.endpointTableModel.endpoints = {"GET|/lol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 200

            cb.fuzzButtonClicked(GenericMock())

            self.assertEquals(state.perRequestExecutorService.submit.call_count, 0)

    def testMarksEndpointsAsFuzzed(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = False
            em.setFuzzed = GenericMock()
            requestA = GenericMock()

            em.requests = [requestA]
            state.endpointTableModel.endpoints = {"GET|/lol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 200

            cb.fuzzButtonClicked(GenericMock())

            self.assertEquals(state.perRequestExecutorService.submit.call_count, 1)
            self.assertEquals(state.endpointTableModel.setFuzzed.call_count, 1)

    def testMarksEndpointsAsFuzzedOnlyIfReproducible(self):
        with self.mockUtilityCalls():
            cb, state, burpCallbacks = self._ctc()

            em = GenericMock()
            em.fuzzed = False
            em.setFuzzed = GenericMock()
            requestA = GenericMock()

            utility.counter = 0
            def wasReproducible():
                if utility.counter == 0:
                    utility.counter += 1
                    return True
                else:
                    return False

            requestA.wasReproducible = wasReproducible

            em.requests = [requestA]
            state.endpointTableModel.endpoints = {"GET|/lol": em}
            requestA.analyzedResponse.statusCode = 200
            requestA.repeatedAnalyzedResponse.statusCode = 200

            cb.fuzzButtonClicked(GenericMock())

            self.assertEquals(state.perRequestExecutorService.submit.call_count, 1)
            self.assertEquals(state.endpointTableModel.setFuzzed.call_count, 0)
            self.assertEquals(ui.sendMessageToSlack.call_count, 1)

    def testGetInsertionPoints(self):
        cb, state, burpCallbacks = self._ctc()

        request = GenericMock()
        parameter = GenericMock()
        parameter.name = "lol"
        parameter.value = "lol"
        parameter.type = 1
        request.repeatedAnalyzedRequest.parameters = [parameter, parameter, parameter]

        insertionPoints = cb.getInsertionPoints(request)
        self.assertEquals(len(insertionPoints), 3)

    def testGetInsertionPointsPath(self):
        cb, state, burpCallbacks = self._ctc()

        headers = ArrayList()
        headers.add("GET /folder1/folder1/file.php HTTP/1.1")
        headers.add("Host: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = cb.getInsertionPoints(request)
        self.assertEquals(len(insertionPoints), 3)
        self.assertEquals(insertionPoints[0].type, IScannerInsertionPoint.INS_URL_PATH_FOLDER)
        self.assertEquals(insertionPoints[1].type, IScannerInsertionPoint.INS_URL_PATH_FOLDER)
        self.assertEquals(insertionPoints[2].type, IScannerInsertionPoint.INS_URL_PATH_FILENAME)

    def testGetInsertionPointsPathQueryString(self):
        cb, state, burpCallbacks = self._ctc()

        headers = ArrayList()
        headers.add("GET /folder1/folder1/file.php?lel=true&lala=1 HTTP/1.1")
        headers.add("Host: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = cb.getInsertionPoints(request)
        self.assertEquals(len(insertionPoints), 3)
        self.assertEquals(insertionPoints[2].type, IScannerInsertionPoint.INS_URL_PATH_FILENAME)
        self.assertEquals(insertionPoints[2].value, "file.php")

    def testBuildRequestPath(self):
        cb, state, burpCallbacks = self._ctc()

        firstLine = "GET /folder1/folder1/file.php HTTP/1.1"
        secondLine = "Host: example.org"

        headers = ArrayList()
        headers.add(firstLine)
        headers.add(secondLine)


        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers
        request.repeatedHttpRequestResponse.request = String(firstLine + "\r\n" + secondLine + "\r\n").getBytes()

        utility.called = False
        def raises(*args):
            utility.called = True
            raise IllegalArgumentException()

        burpCallbacks.helpers.updateParameter = raises

        insertionPoints = cb.getInsertionPoints(request)

        insertionPoints[0].updateContentLength = lambda x: x
        insertionPoints[1].updateContentLength = lambda x: x
        insertionPoints[2].updateContentLength = lambda x: x

        ret = insertionPoints[0].buildRequest(String("LOLLOLLOL").getBytes())

        self.assertTrue(utility.called)
        self.assertTrue(str(String(ret)).startswith("GET /LOLLOLLOL/folder1/file.php HTTP/1.1"))

        ret = insertionPoints[1].buildRequest(String("LOLLOLLOL").getBytes())
        self.assertTrue(str(String(ret)).startswith("GET /folder1/LOLLOLLOL/file.php HTTP/1.1"))

        ret = insertionPoints[2].buildRequest(String("LOLLOLLOL").getBytes())
        self.assertTrue(str(String(ret)).startswith("GET /folder1/folder1/LOLLOLLOL HTTP/1.1"))

    def testBuildRequestJson(self):
        callbacks = GenericMock()

        request = String("POST / HTTP/1.1\r\nHost:lelele\r\nContent-length: lelel\r\n\r\n{\"param\":\"value\"}\r\n").getBytes()

        callbacks.helpers.updateParameter.raise = UnsupportedOperationException

        sip = ScannerInsertionPoint(callbacks, request, "name", "value", IScannerInsertionPoint.INS_PARAM_JSON, 65, 70)
        sip.updateContentLength = lambda x: x

        ret = sip.buildRequest(String("lol").getBytes())
        self.assertTrue('{"param":"lol"}' in str(String(ret)))

        ret = sip.buildRequest(String("herecomethe\"quotes").getBytes())
        self.assertTrue('{"param":"herecomethe\\"quotes"}' in str(String(ret)))

    def testBuildRequestJsonNumbers(self):
        callbacks = GenericMock()

        request = String("POST / HTTP/1.1\r\nHost:lelele\r\nContent-length: 16\r\n\r\n{\"param\":1234}\r\n").getBytes()

        callbacks.helpers.updateParameter.raise = UnsupportedOperationException

        sip = ScannerInsertionPoint(callbacks, request, "name", "value", IScannerInsertionPoint.INS_PARAM_JSON, 61, 65)
        sip.updateContentLength = lambda x: x

        ret = sip.buildRequest(String("lol").getBytes())
        self.assertTrue('{"param":"lol"}' in str(String(ret)))

        ret = sip.buildRequest(String("herecomethe\"quotes").getBytes())
        self.assertTrue('{"param":"herecomethe\\"quotes"}' in str(String(ret)))

    def testBuildRequestUpdatesContentLength(self):
        callbacks = GenericMock()

        request = String("POST / HTTP/1.1\r\nHost:lelele\r\nContent-length: 16\r\n\r\n{\"param\":1234}\r\n").getBytes()

        callbacks.helpers.updateParameter.raise = UnsupportedOperationException

        sip = ScannerInsertionPoint(callbacks, request, "name", "value", IScannerInsertionPoint.INS_PARAM_JSON, 61, 65)
        sip.updateContentLength = GenericMock()

        ret = sip.buildRequest(String("lol").getBytes())

        self.assertEquals(sip.updateContentLength.call_count, 1)

if __name__ == '__main__':
    unittest.main()
