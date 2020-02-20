from benteveo_toolbox import BurpExtender
from burp import IBurpExtenderCallbacks, IExtensionHelpers, IScannerInsertionPoint
from implementations import ScannerInsertionPoint
from java.lang import String, IllegalArgumentException, UnsupportedOperationException
from java.net import URL
from java.util import ArrayList
from models import EndpointModel, RequestModel, ReplacementRuleModel
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel
from ui import ToolboxCallbacks, STATUS_OK, STATUS_FAILED
from tests import GenericMock, TestException, raise_exception, BaseTestClass
import math
import operator
import ui
import unittest
import utility
import benteveo_toolbox

utility.INSIDE_UNIT_TEST = True

class TestToolbox(BaseTestClass):
    """
    Main testing class. Contains tests for sections of the code that don't pertain to more specific test files.
    """
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
        self.assertEqual(len(etm.endpoints["GET|http://www.example.org/users"].requests), etm.MAX_REQUESTS_PER_ENDPOINT)

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

        extension = GenericMock()
        scanner = GenericMock()
        extension.getScannerChecks.return_value = [scanner]
        cb.extensions = [("scanner_name", extension)]
        cb.fuzzRequestModel(GenericMock())

        self.assertEquals(state.executorService.submit.call_count, 5)

        state.executorService.submit.return_value.isDone = raise_exception

        callsIsDone = False
        try:
            cb.fuzzRequestModel(GenericMock())
        except TestException:
            callsIsDone = True

        self.assertTrue(callsIsDone, "Calls is done.")

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
        request.repeatedAnalyzedRequest.headers = [parameter, parameter, parameter] # gonna skip the first line in the header

        insertionPoints = cb.getInsertionPoints(request, False)
        self.assertEquals(len(insertionPoints), 5)

    def testGetInsertionPointsOnlyParameters(self):
        cb, state, burpCallbacks = self._ctc()

        request = GenericMock()
        parameter = GenericMock()
        parameter.name = "lol"
        parameter.value = "lol"
        parameter.type = 1
        request.repeatedAnalyzedRequest.parameters = [parameter, parameter, parameter]
        request.repeatedAnalyzedRequest.headers = [parameter, parameter, parameter] # gonna skip the first line in the header

        onlyParameters = True
        insertionPoints = cb.getInsertionPoints(request, onlyParameters)
        self.assertEquals(len(insertionPoints), 3)

    def testGetInsertionPointsPath(self):
        cb, state, burpCallbacks = self._ctc()

        headers = ArrayList()
        headers.add("GET /folder1/folder1/file.php HTTP/1.1")
        headers.add("Host: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = cb.getPathInsertionPoints(request)
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

        insertionPoints = cb.getPathInsertionPoints(request)
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

        insertionPoints = cb.getInsertionPoints(request, False)

        insertionPoints[0].updateContentLength = lambda x: x
        insertionPoints[1].updateContentLength = lambda x: x
        insertionPoints[2].updateContentLength = lambda x: x

        burpCallbacks.helpers.urlEncode.return_value = "LOLLOLLOL"
        ret = insertionPoints[0].buildRequest(String("LOLLOLLOL").getBytes())

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

    def testBuildRequestXml(self):
        callbacks = GenericMock()

        request = String("POST / HTTP/1.1\r\nHost:lelele\r\nContent-length: lelel\r\n\r\n<xml>lol</xml>\r\n").getBytes()

        callbacks.helpers.updateParameter.raise = UnsupportedOperationException

        sip = ScannerInsertionPoint(callbacks, request, "name", "value", IScannerInsertionPoint.INS_PARAM_XML, 60, 63)
        sip.updateContentLength = lambda x: x

        ret = sip.buildRequest(String("evil <awfafw ''\"").getBytes())

        self.assertTrue("<xml>evil &lt;awfafw &apos;&apos;&quot;</xml>" in str(String(ret)))

    def testBuildRequestXmlAttr(self):
        callbacks = GenericMock()

        request = String("POST / HTTP/1.1\r\nHost:lelele\r\nContent-length: lelel\r\n\r\n<xml a=\"lol\">whatever</xml>\r\n").getBytes()

        callbacks.helpers.updateParameter.raise = UnsupportedOperationException

        sip = ScannerInsertionPoint(callbacks, request, "name", "value", IScannerInsertionPoint.INS_PARAM_XML_ATTR, 63, 66)
        sip.updateContentLength = lambda x: x

        ret = sip.buildRequest(String("evil <awfafw ''\"").getBytes())

        self.assertTrue("<xml a=\"evil &lt;awfafw &apos;&apos;&quot;\">whatever</xml>" in str(String(ret)))

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

    def testGetInsertionPointsPathRoot(self):
        cb, state, burpCallbacks = self._ctc()

        headers = ArrayList()
        headers.add("GET / HTTP/1.1")
        headers.add("Host: example.org")
        headers.add("Custom-header: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = cb.getPathInsertionPoints(request)
        self.assertEquals(len(insertionPoints), 0)

    def testGetInsertionPointsHeaders(self):
        cb, state, burpCallbacks = self._ctc()

        headers = ArrayList()
        headers.add("GET / HTTP/1.1")
        headers.add("Host: example.org")
        headers.add("Custom-header: LOL")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = cb.getInsertionPoints(request, False)
        self.assertEquals(len(insertionPoints), 2)
        self.assertEquals(insertionPoints[0].type, IScannerInsertionPoint.INS_HEADER)
        self.assertEquals(insertionPoints[0].baseValue, "example.org")
        self.assertEquals(insertionPoints[1].type, IScannerInsertionPoint.INS_HEADER)
        self.assertEquals(insertionPoints[1].baseValue, "LOL")

    def testInsertionPointHeaderBuildRequest(self):
        callbacks = GenericMock()

        request = String("GET / HTTP/1.1\r\nHost: lelele\r\n\r\n").getBytes()

        sip = ScannerInsertionPoint(callbacks, request, "Host", "lelele", IScannerInsertionPoint.INS_HEADER, 22, 28)
        sip.updateContentLength = lambda x: x

        ret = sip.buildRequest(String("lol").getBytes())
        self.assertTrue("Host: lol" in str(String(ret)))

if __name__ == '__main__':
    unittest.main()
