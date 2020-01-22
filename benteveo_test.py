import math
import unittest
import operator
from java.awt import Component
from benteveo_toolbox import BurpExtender

class GenericMock(object):
    calls = {}
    def __getattr__(self, name):
        def method(*args):

            try:
                self.calls[name] += 1
            except KeyError:
                self.calls[name] = 1

            return GenericMock()

        return method

    def getComponent(self, *args):
        class ComponentMock(Component):
            pass
            
        return ComponentMock()

class TestToolbox(unittest.TestCase):

    def testCanRunMainWithoutCrashing(self):
        be = BurpExtender()
        be.registerExtenderCallbacks(GenericMock())


if __name__ == '__main__':
    unittest.main()
