from burp import IBurpExtenderCallbacks, IExtensionHelpers
from java.util import ArrayList
from java.util import Arrays
import importlib
import json
import re
import string
import sys
import urllib2

# Constants for the add replacement form.
REPLACE_HEADER_NAME = "Replace by header name"

# Regular expressions that match an ID.
regex = [
    re.compile("[a-f0-9]{64}"), # 748bbea58bb5db34e95d02edb2935c0f25cb1593e5ab837767e260a349c02ca7
    re.compile("[0-9]{13}-[a-f0-9]{64}"), # 1579636429347-c568eba49ad17ef37b9db4ea42466b71e065481ddbc2f5a63503719c44dfb6ee
    re.compile("S-1.*"), # S-1-5-21-2931253742-2981233768-3707659581-1108%26d-90670d8a68
    re.compile("^[0-9]+$"), # 121251251
    re.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"), # 1da4b1de-c0af-4e11-8d44-97de90728db3
]

class NoSuchHeaderException(Exception):
    pass

def apply_rules(callbacks, rules, request):
    """
    Performs the modification of a request according to the user's specification and returns a byte array with the modified request.

    Args:
        callbacks: the burp callbacks object.
        rules: as returned by the ReplacementRuleTableModel
        request: a byte[] object that should be modified.

    Returns:
        tuple: returns the modified request as the first value and the number of modifications applied as a second value
    """
    modified = False
    nbModifications = 0
    for rule in rules:
        if rule.type == REPLACE_HEADER_NAME:
            modified, newRequest = replace_header_name(callbacks, rule, request)

        if modified:
            nbModifications += 1
            request = newRequest

    return nbModifications, request

def replace_header_name(callbacks, rule, request):
    """
    Finds header name and replaces it with a new value, provided by the user.

    Args:
        callbacks: the burp callbacks object.
        rule: the rule that we should apply.
        request: a byte[] object that should be modified.

    Returns:
        tuple: the first element is a boolean that indicates whether the request was modified and the second one is the modified request or None if we didn't modify the request.
    """
    helpers = callbacks.helpers
    analyzedRequest = helpers.analyzeRequest(request)
    headers = analyzedRequest.headers

    modified = False
    newHeaders = ArrayList()
    for header in headers:
        splat = header.split(":")
        if len(splat) >= 2:
            name, value = splat[0], splat[1]
        else:
            newHeaders.add(header)
            continue # First line of header doesn't have ":"

        if name.lower().strip() == rule.search.lower().strip():
            newHeaders.add("%s: %s" % (name, rule.replacement))
            modified = True
        else:
            newHeaders.add(header)

    if modified:
        body = Arrays.copyOfRange(request, analyzedRequest.bodyOffset, len(request));
        return modified, helpers.buildHttpMessage(newHeaders, body)
    else:
        return modified, None


def get_header(callbacks, request, header_name):
    """
    Attempts to read a header from a request.

    If there are multiple headers in the request, it returns the first. If the header is not present, it raises an exception.

    Args:
        callbacks: the burp callbacks object
        request: the byte[] object that should be parsed.
        header_name: the header that should be retrieved. The comparison will be case-insensitive.

    Returns:
        string: the header's value.

    Raises:
        NoSuchHeaderException: if the header does not exist.
    """
    analyzedRequest = callbacks.helpers.analyzeRequest(request)
    headers = analyzedRequest.headers

    for header in headers:
        try:
            name, value = header.split(":")
        except ValueError:
            continue # Always happens on the first line of the request.

        name = name.strip().lower()
        value = value.strip()

        if name == header_name.lower():
            return value

    raise NoSuchHeaderException("Header not found.")

def log(message):
    """
    Writes a log to Burp's stdout logging.

    This is a simple wrapper around print in case we want to do something more fancy in the future.

    Args:
        Message to print.
    """
    print message +"\n",

def sendMessageToSlack(message):
    """
    Sends a message to the Benteveo Kiwi slack channel.

    Doesn't use burps APIs so the request is not registered by burp.

    Args:
        message: the message to send.
    """
    url = 'https://hooks.slack.com/services/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'
    params = {'text': message}
    req = urllib2.Request(url, headers = {"Content-Type": "application/json"}, data = json.dumps(params))
    urllib2.urlopen(req)

class BurpCallWrapper(IBurpExtenderCallbacks, IExtensionHelpers):
    """
    Our own custom implementation of the burp extender callbacks and helper functions.

    It is used for communication with the imported modules. It mainly records calls and then forwards them to the real IBurpExtenderCallbacks/IExtensionHelpers implementation.
    """

    helpersObject = None
    wrappedObject = None
    calls = None

    def __init__(self, wrappedObject):
        """
        Main constructor.

        Args:
            wrappedObject: the real burp callbacks/helper object to wrap, i.e. callbacks or helpers.
        """
        self.wrappedObject = wrappedObject
        self.calls = {}
        self.helpersObject = None

    def setExtensionName(self, name):
        """
        Prevent this call from reaching burp callbacks as this causes issues.
        """
        pass

    def __getattribute__(self, name):
        """
        Called when somebody attempts to access an attribute of this class, such as a function.

        The purpose of this function is to record the call arguments for later access.

        Args:
            name: the name of the attribute.
        """
        # If method is implemented here and not in the interface, return directly.
        if name in object.__getattribute__(self, "__class__").__dict__:
            return object.__getattribute__(self, name)

        wrappedObject = self.wrappedObject
        calls = self.calls

        attr = getattr(wrappedObject, name)
        isFunction = hasattr(attr, '__call__')

        if isFunction:
            def wrap(*args, **kwargs):
                if not name in calls:
                    calls[name] = []

                calls[name].append((args, kwargs))
                ret = attr(*args, **kwargs)
                return ret

            return wrap
        else:
            return attr

class BurpExtension(object):
    """
    Stores information regarding a loaded burp extension
    """

    def __init__(self, callWrapper):
        """
        Main constructor.

        Args:
            callWrapper: a BurpCallWrapper object as passed to burpExtender.registerExtenderCallbacks
        """
        self.calls = callWrapper.calls

    def getSimpleCalls(self, func):
        calls = []
        try:
            for call in self.calls[func]:
                args, kwargs = call
                calls.append(args[0])
        except KeyError:
            pass

        return calls

    def getScannerChecks(self):
        return self.getSimpleCalls('registerScannerCheck')

    def getExtensionStateListeners(self):
        return self.getSimpleCalls('registerExtensionStateListener')

    def getContextMenuFactories(self):
        return self.getSimpleCalls('registerContextMenuFactory')

def getClass(className):
    """
    Given a class name, it gets a reference to it that can later be instantiated.

    It does not make use of `importlib.import_module` because Java modules cannot be imported in this way. See https://stackoverflow.com/a/44040971 for more information

    Args:
        className: the class name to get a reference to. You should not pass untrusted input to this function because it is exec'ed.
    """

    for c in className:
        if c != '.' and c not in string.ascii_letters:
            raise Exception()

    exec "import %s as tmpClass" % className
    return tmpClass

def importBurpExtension(jarFile, burpExtenderClass, callbacks):
    """
    Imports a burp module given the location of the JAR file and it's main class.

    It does this by adding the jar to the sys.path, importing the class and calling it with a wrapper that records interactions to the callbacks objects.

    Args:
        jarFile: the location in disk where the extension's JAR file is located.
        burpExtenderClass: the name of the burpExtender implementation.
        callbacks: the burp callbacks object.
    """
    sys.path.append(jarFile)

    burpExtenderImpl = getClass(burpExtenderClass)
    burpExtender = burpExtenderImpl()

    callbacksWrapper = BurpCallWrapper(callbacks)
    burpExtender.registerExtenderCallbacks(callbacksWrapper)

    return BurpExtension(callbacksWrapper)
