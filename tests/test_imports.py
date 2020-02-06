from tests import GenericMock, TestException, raise_exception, BaseTestClass, ImportCallbackMock
import utility

utility.INSIDE_UNIT_TEST = True

class TestImports(BaseTestClass):
    def testImportBase(self):
        callbacks = ImportCallbackMock()
        burpExtension = utility.importBurpExtension("lib/backslash-powered-scanner-fork.jar", 'burp.BurpExtender', callbacks)

        self.assertEquals(len(burpExtension.getActiveScanners()), 1)

    def testAnother(self):
        pass
