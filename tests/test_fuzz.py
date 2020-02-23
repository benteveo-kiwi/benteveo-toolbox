from tests import GenericMock, TestException, raise_exception, BaseTestClass, ImportCallbackMock
import utility
from fuzz import FuzzRunner

utility.INSIDE_UNIT_TEST = True

class TestFuzz(BaseTestClass):
    def testCanInstantiateWithoutCrashing(self):
        callbacks = ImportCallbackMock()
        fr = FuzzRunner()
