from burp import IBurpExtenderCallbacks, IExtensionHelpers, IScannerInsertionPoint
from fuzz import FuzzRunner, InsertionPointsGenerator
from implementations import ScannerInsertionPoint
from java.lang import String, IllegalArgumentException, UnsupportedOperationException
from java.util import ArrayList
from tests import GenericMock, TestException, raise_exception, BaseTestClass, ImportCallbackMock
import utility

utility.INSIDE_UNIT_TEST = True

class TestFuzz(BaseTestClass):

    def _ipg(self):
        callbacks = GenericMock()
        ipg = InsertionPointsGenerator(callbacks)

        return ipg, callbacks

    def testGetInsertionPointsPathRoot(self):
        ipg, callbacks = self._ipg()

        headers = ArrayList()
        headers.add("GET / HTTP/1.1")
        headers.add("Host: example.org")
        headers.add("Custom-header: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = ipg.getPathInsertionPoints(request)

        self.assertEquals(len(insertionPoints), 0)

    def testGetInsertionPointsHeaders(self):
        ipg, callbacks = self._ipg()

        headers = ArrayList()
        headers.add("GET / HTTP/1.1")
        headers.add("Host: example.org")
        headers.add("Custom-header: LOL")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = ipg.getInsertionPoints(request, False)
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

    def testGetInsertionPointsPathQueryString(self):
        ipg, callbacks = self._ipg()
        cb, state, burpCallbacks = self._ctc()

        headers = ArrayList()
        headers.add("GET /folder1/folder1/file.php?lel=true&lala=1 HTTP/1.1")
        headers.add("Host: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = ipg.getPathInsertionPoints(request)
        self.assertEquals(len(insertionPoints), 3)
        self.assertEquals(insertionPoints[2].type, IScannerInsertionPoint.INS_URL_PATH_FILENAME)
        self.assertEquals(insertionPoints[2].value, "file.php")

    def testGetInsertionPoints(self):
        ipg, callbacks = self._ipg()

        request = GenericMock()
        parameter = GenericMock()
        parameter.name = "lol"
        parameter.value = "lol"
        parameter.type = 1
        request.repeatedAnalyzedRequest.parameters = [parameter, parameter, parameter]
        request.repeatedAnalyzedRequest.headers = [parameter, parameter, parameter] # gonna skip the first line in the header

        insertionPoints = ipg.getInsertionPoints(request, False)
        self.assertEquals(len(insertionPoints), 5)

    def testGetInsertionPointsOnlyParameters(self):
        ipg, callbacks = self._ipg()

        request = GenericMock()
        parameter = GenericMock()
        parameter.name = "lol"
        parameter.value = "lol"
        parameter.type = 1
        request.repeatedAnalyzedRequest.parameters = [parameter, parameter, parameter]
        request.repeatedAnalyzedRequest.headers = [parameter, parameter, parameter] # gonna skip the first line in the header

        onlyParameters = True
        insertionPoints = ipg.getInsertionPoints(request, onlyParameters)
        self.assertEquals(len(insertionPoints), 3)

    def testGetInsertionPointsPath(self):
        ipg, callbacks = self._ipg()

        headers = ArrayList()
        headers.add("GET /folder1/folder1/file.php HTTP/1.1")
        headers.add("Host: example.org")

        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers

        insertionPoints = ipg.getPathInsertionPoints(request)
        self.assertEquals(len(insertionPoints), 3)
        self.assertEquals(insertionPoints[0].type, IScannerInsertionPoint.INS_URL_PATH_FOLDER)
        self.assertEquals(insertionPoints[1].type, IScannerInsertionPoint.INS_URL_PATH_FOLDER)
        self.assertEquals(insertionPoints[2].type, IScannerInsertionPoint.INS_URL_PATH_FILENAME)
