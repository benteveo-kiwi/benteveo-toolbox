from tests import GenericMock, TestException, raise_exception, BaseTestClass, ImportCallbackMock
import utility

utility.INSIDE_UNIT_TEST = True

class TestImports(BaseTestClass):
    def testImportBase(self):
        callbacks = ImportCallbackMock()
        burpExtension = utility.importBurpExtension("lib/backslash-powered-scanner-fork.jar", 'burp.BackslashBurpExtender', callbacks)

        self.assertEquals(len(burpExtension.getScannerChecks()), 1)
        self.assertEquals(len(burpExtension.getExtensionStateListeners()), 2)
        self.assertEquals(len(burpExtension.getContextMenuFactories()), 1)

    def testImportResourcesDontCollide(self):
        """
        Sometimes imported JARs have resources, such as wordlists with the same names. This results in runtime errors that are hard to detect. The same can be said for class names.

        This test checks that this doesn't happen.
        """
        self.assertTrue(False)
