from java.util import ArrayList
from java.util import Arrays

REPLACE_HEADER_NAME = "Replace by header name"

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
        try:
            name, value = header.split(":")
        except ValueError:
            newHeaders.add(header)
            continue # Always happens on the first line of the request.

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
    print(message)
