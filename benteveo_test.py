import math
import unittest
import operator
from java.awt import Component
from benteveo_toolbox import BurpExtender
from classes import EndpointTableModel

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
        return self.return_value

    def getComponent(self, *args):
        class ComponentMock(Component):
            pass

        return ComponentMock()

class TestToolbox(unittest.TestCase):

    def testCanRunMainWithoutCrashing(self):
        be = BurpExtender()
        mock = GenericMock()
        be.registerExtenderCallbacks(mock)

        print mock.setExtensionName
        self.assertEqual(mock.setExtensionName.call_count, 1)

    def testGenerateEndpointHash(self):
        state = GenericMock()
        etm = EndpointTableModel(state)

        ret = state.helpers.analyzeRequest.return_value
        ret.method = "GET"
        ret.url = "http://www.example.org/users"

        hash = etm.generateEndpointHash(GenericMock())

        self.assertEquals(hash, "GET|http://www.example.org/users")


if __name__ == '__main__':
    unittest.main()
