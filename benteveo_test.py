import math
import unittest
import operator
from collections import OrderedDict
from java.awt import Component
from benteveo_toolbox import BurpExtender
from classes import EndpointTableModel, ToolboxCallbacks, EndpointModel, RequestModel
from java.net import URL

class GenericMock(object):
    """
    A generic mocking class that accepts calls to any method without crashing.

    Because we're using jython, installing commonly used mocking frameworks takes more than one command and could make creating a testing environment more complicated.
    """

    call_count = 0
    mocked = {}

    def __getattr__(self, name):

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
        self.call_count += 1
        self.call_args = args
        return self.return_value

    def getComponent(self, *args):
        class ComponentMock(Component):
            pass

        return ComponentMock()

    def loadExtensionSetting(self, *args):
        return "setting"

class TestToolbox(unittest.TestCase):

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

        request = RequestModel(GenericMock())

        hash = method + "|" + url

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


    def testCanRunMainWithoutCrashing(self):
        be = BurpExtender()
        mock = GenericMock()
        be.registerExtenderCallbacks(mock)

        self.assertEqual(mock.setExtensionName.call_count, 1)

    def testGenerateEndpointHash(self):
        state = GenericMock()
        callbacks = GenericMock()
        etm = EndpointTableModel(state, callbacks)

        mockRequestInfo = GenericMock()
        mockRequestInfo.method = "GET"
        mockRequestInfo.url = URL("http://www.example.org/users")

        hash, _, _ = etm.generateEndpointHash(mockRequestInfo)

        self.assertEquals(hash, "GET|http://www.example.org/users")

    def testRefreshPersistsSettings(self):
        state = GenericMock()
        burpCallbacks = GenericMock()
        cb = ToolboxCallbacks(state, burpCallbacks)

        state.scopeTextArea.getText.return_value = "https://example.com/\nhttps://example.org/\n"
        burpCallbacks.getSiteMap.return_value = [GenericMock(),GenericMock(),GenericMock()]

        cb.refreshButtonClicked(GenericMock())

        self.assertEquals(state.scopeTextArea.getText.call_count, 1)
        self.assertEquals(burpCallbacks.saveExtensionSetting.call_count, 1)
        self.assertEquals(burpCallbacks.getSiteMap.call_count, 2)
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
        state = GenericMock()
        callbacks = GenericMock()
        etm = EndpointTableModel(state, callbacks)

        ret = callbacks.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = URL("http://www.example.org/users?count=50")

        etm.add(GenericMock())

        self.assertEqual(len(etm.endpoints), 1)
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].url, "http://www.example.org/users")
        self.assertEqual(etm.endpoints["GET|http://www.example.org/users"].method, "GET")

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

        self.assertEquals(state.requestsTableModel.updateRequests.call_count, 1)
        self.assertEquals(len(state.requestsTableModel.updateRequests.call_args[0]), 2)



if __name__ == '__main__':
    unittest.main()
