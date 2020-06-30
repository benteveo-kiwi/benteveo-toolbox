from burp import IBurpExtenderCallbacks, IExtensionHelpers
from java.lang import Runnable, String
from java.util import ArrayList
from java.util import Arrays
import functools
import importlib
import json
import logging
import re
import string
import sys
import time
import urllib2

# Whether we are running inside a unit test.
INSIDE_UNIT_TEST = False

# Application logger.
logger = None

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
    """
    Raised when a header is required to be replaced but does not exist.
    """
    pass

class ShutdownException(Exception):
    """
    Raised on threads to cause a failure that will trigger the thread to naturally die.
    """
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

    print "lelelele", headers, analyzedRequest
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

def resend_request_model(state, callbacks, request):
    """
    Resends a request model and update the RequestModel object with the new response.

    Args:
        state: the global state object.
        callbacks: the burp callbacks object.
        request: the RequestModel to resend.
    """
    target = request.httpRequestResponse.httpService

    path = request.analyzedRequest.url.path
    if "logout" in path:
        log("Ignoring request to %s to avoid invalidating the session." % path)
        return

    nbModified, modifiedRequest = apply_rules(callbacks,
                                            state.replacementRuleTableModel.rules,
                                            request.httpRequestResponse.request)
    if nbModified == 0:
        log("Warning: Request for '%s' endpoint was not modified." % path)

    newResponse = callbacks.makeHttpRequest(target, modifiedRequest)
    state.endpointTableModel.update(request, newResponse)

def setupLogging(logLevel=None):
    """
    Configure logging for this application.

    Args:
        logLevel: the logLevel to use for this run.
    """

    if not logLevel:
        logLevel = logging.DEBUG

    format = '[%(levelname)s %(asctime)s]: %(message)s'

    logging.basicConfig(format=format, level=logLevel, stream=sys.stderr)

    global logger

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logLevel)
    formatter = logging.Formatter(format)
    handler.setFormatter(formatter)

    logger = logging.getLogger("benteveo-toolbox")
    logger.propagate = False
    logger.addHandler(handler)

def log(message):
    """
    Logs an INFO message.

    Args:
        Message to print.
    """
    logger.info(message)

class LogDecorator(object):
    """
    A debugging decorator that records function calls and arguments.
    """
    def __init__(self):
        """
        Main constructor
        """
        self.logger = logging.getLogger('benteveo-toolbox')

    def __call__(self, fn):
        """
        Main wrapper. For more information see https://dev.to/mandrewcito/a-tiny-python-log-decorator-1o5m
        """
        @functools.wraps(fn)
        def decorated(*args, **kwargs):
            try:
                self.logger.debug("{0} - {1} - {2}".format(fn.__name__, args, kwargs))
                result = fn(*args, **kwargs)
                self.logger.debug("{0} = {1}".format(fn.__name__, result))
                return result
            except Exception as ex:
                self.logger.debug("Exception {0}".format(ex))
                raise ex
            return result
        return decorated

def sendMessageToSlack(callbacks, message):
    """
    Sends a message to the Benteveo Kiwi slack channel.

    Makes use of Burp APIs which are not really designed for this kind of usage because there are incompatibilities between the SSL client that Jython uses and Slack services.

    Args:
        callbacks: the burp callbacks object. This is required in order to perform the request using burp's API.
        message: the message to send.
    """
    body = "{'text':%s}" % json.dumps(message)
    contentLength = len(body)

    request = "POST /services/TEVNC7KU7/BTGDUCE6Q/Ic0Rw5eOxfQdAFMLhRPSYF2Y HTTP/1.1\r\nHost: hooks.slack.com\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s""" % (contentLength, body)
    callbacks.makeHttpRequest('hooks.slack.com', 443, True, String(request).getBytes())

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


class PythonFunctionRunnable(Runnable):
    """
    A python implementation of Runnable.
    """
    def __init__(self, method, args=[], kwargs={}):
        """
        Stores these variables for when the run() method is called.

        Args:
            method: the method to call
            args: args to pass
            kwargs: kwargs to pass
        """
        self.method = method
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """
        Method that gets called by the new thread.
        """
        try:
            self.method(*self.args, **self.kwargs)
        except ShutdownException:
            log("Thread shutting down")
            raise
        except:
            logging.error("Exception in thread", exc_info=True)
            raise

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

def sleep(state, sleepTime):
    """
    Sleeps for a certain time. Checks for state.shutdown and if it is true raises an unhandled exception that crashes the thread. When inside a test, does nothing.

    Args:
        state: the state object.
        sleepTime: the time in seconds.
    """

    if INSIDE_UNIT_TEST:
        return

    if state.shutdown:
        log("Thread shutting down.")
        raise ShutdownException()

    time.sleep(sleepTime)

def resend_session_check(state, callbacks, textAreaText):
    """
    Sends session check request and inspects the response. If the response seems reproducible after applying the modifications required by the user, then the function returns true.

    Args:
        state: the global state object.
        callbacks: the burp callbacks object.
        textAreaText: the check request text as input in the textarea.

    Returns:
        (boolean, analyzedResponse): whether the session check request succeeded, and the response to the request we've just sent to verify this.
    """
    baseRequestString = re.sub(r"(?!\r)\n", "\r\n", textAreaText)
    baseRequest = callbacks.helpers.stringToBytes(baseRequestString)
    hostHeader = get_header(callbacks, baseRequest, "host")

    target = callbacks.helpers.buildHttpService(hostHeader, 443, "https")
    nbModified, modifiedRequest = apply_rules(callbacks, state.replacementRuleTableModel.rules, baseRequest)
    if nbModified == 0:
        log("Warning: No modifications made to check request.")

    response = callbacks.makeHttpRequest(target, modifiedRequest)
    analyzedResponse = callbacks.helpers.analyzeResponse(response.response)

    if analyzedResponse.statusCode == 200:
        return (True, analyzedResponse)
    else:
        return (False, analyzedResponse)
