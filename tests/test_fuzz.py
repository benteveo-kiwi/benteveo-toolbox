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

    def _fr(self):
        callbacks = GenericMock()
        state = GenericMock()

        extensions = [GenericMock(), GenericMock()]

        fuzzRunner = FuzzRunner(state, callbacks, extensions)

        return fuzzRunner, state, callbacks, extensions

    def testFuzzRequestModel(self):
        fr, state, callbacks, extensions = self._fr()

        extension = GenericMock()
        scanner = GenericMock()
        extension.getScannerChecks.return_value = [scanner]
        fr.extensions = [("scanner_name", extension)]
        fr.fuzzRequestModel(GenericMock())

        self.assertEquals(state.fuzzExecutorService.submit.call_count, 5)

        state.fuzzExecutorService.submit.return_value.isDone = raise_exception

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

    def testBuildRequestPath(self):
        ipg, callbacks = self._ipg()

        firstLine = "GET /folder1/folder1/file.php HTTP/1.1"
        secondLine = "Host: example.org"

        headers = ArrayList()
        headers.add(firstLine)
        headers.add(secondLine)


        request = GenericMock()
        request.repeatedAnalyzedRequest.parameters = []
        request.repeatedAnalyzedRequest.headers = headers
        request.repeatedHttpRequestResponse.request = String(firstLine + "\r\n" + secondLine + "\r\n").getBytes()

        insertionPoints = ipg.getInsertionPoints(request, False)

        insertionPoints[0].updateContentLength = lambda x: x
        insertionPoints[1].updateContentLength = lambda x: x
        insertionPoints[2].updateContentLength = lambda x: x

        callbacks.helpers.urlEncode.return_value = "LOLLOLLOL"
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

    def testGetContextMenuInvocation(self):
        fr, state, callbacks, extensions = self._fr()

        extension = GenericMock()
        scanner = GenericMock()
        extension.getScannerChecks.return_value = [scanner]
        fr.extensions = [("paramminer", extension)] # the paramminer string triggers the clicks.
        fr.fuzzRequestModel(GenericMock())

        self.assertEquals(state.fuzzExecutorService.submit.call_count, 5)

        state.fuzzExecutorService.submit.return_value.isDone = raise_exception

        self.assertTrue(extension.getContextMenuFactories.call_count, 5)


    def testCheckMaxConcurrentRequests(self):
        self.assertTrue(False)
