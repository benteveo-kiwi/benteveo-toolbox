from benteveo_toolbox import IssueChecker
from collections import OrderedDict
from java.awt import Component
from java.lang import String, IllegalArgumentException, UnsupportedOperationException, Class
from java.net import URL
from java.util import ArrayList
from models import EndpointModel, RequestModel, ReplacementRuleModel
from tables import EndpointTableModel, RequestTableModel, ReplacementRuleTableModel
from ui import ToolboxCallbacks, STATUS_OK, STATUS_FAILED
import contextlib
import java.io.File
import java.io.FileOutputStream
import logging
import tempfile
import ui
import unittest
import utility

class BaseTestClass(unittest.TestCase):
    """
    Generic test class that all tests inherit from.
    """

    @classmethod
    def setUpClass(_):
        """
        Main constructor method.
        """
        utility.setupLogging(logLevel=logging.ERROR)

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
        state.shutdown = False


        request = ArrayList()
        request.add("GET / HTTP/1.1")
        request.add("Host: example.org")
        burpCallbacks.helpers.analyzeRequest.return_value.headers = request

        cb = ToolboxCallbacks(state, burpCallbacks)
        cb.sleep = GenericMock()

        extension = GenericMock()
        scanner = GenericMock()
        extension.getScannerChecks.return_value = [scanner]
        cb.extensions = [("scanner_name", extension)]

        return cb, state, burpCallbacks

    def _crrtm(self):
        """
        Create ReplacementRuleTableModel convenience method.
        """
        return ReplacementRuleTableModel()

    def _ic(self):
        """
        Create IssueChecker convenience method
        """
        state = GenericMock()
        callbacks = GenericMock()
        callbacks.getScanIssues.return_value = []

        ic = IssueChecker(state, callbacks)

        return ic, state, callbacks

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
        if args[0] == "scopes":
            return None
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

class ImportCallbackMock(GenericMock):

    def getStdout(self):
        """
        Mocks for import tests.
        """
        with tempfile.NamedTemporaryFile() as tmpFile:
            file = java.io.File(tmpFile.name)
            tmpFile.close()

            fileOutputStream = java.io.FileOutputStream(file)

            return fileOutputStream

    def getStderr(self):
        """
        Mocks for import tests.
        """
        with tempfile.NamedTemporaryFile() as tmpFile:
            file = java.io.File(tmpFile.name)
            tmpFile.close()

            fileOutputStream = java.io.FileOutputStream(file)

            return fileOutputStream

    def setExtensionName(self, arg):
        """
        Mocks for import tests.
        """
        pass

    def analyzeResponseVariations(self, arg):
        """
        Mocks for import tests.
        """
        pass

    def registerScannerCheck(self, *args):
        """
        Mocks for import tests.
        """
        pass

    def registerExtensionStateListener(self, *args):
        """
        Mocks for import tests.
        """
        pass

    def registerContextMenuFactory(self, *args):
        """
        Mocks for import tests.
        """
        pass

    def getHelpers(self):
        """
        Mocks for import tests.
        """
        import burp.IExtensionHelpers
        class Mock(GenericMock, burp.IExtensionHelpers):
            def analyzeResponseVariations(self, *args, **kwargs):
                return
        return Mock()


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
