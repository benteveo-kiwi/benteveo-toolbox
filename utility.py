
class InvalidHeaderException(Exception):
    pass

def perform_request(callbacks, httpService, request):
    """
    Performs a http request against an external server, and returns a httpRequestResponse instance.

    This method makes use of Burp's APIs to make the request, which is best practice when programming burp because it ensures the user's configuration is respected.

    Args:
        callbacks: the burp callback object.
        httpService: an instance of an object that implements IHttpService.
        request: a byte[] object that should be sent.
    """

def apply_rules(rules, request):
    """
    Performs the modification of a request according to the user's specification and returns a byte array with the modified request.

    Args:
        rules: as returned by the ReplacementRuleTableModel
        request: a byte[] object that should be modified.
    """

def get_header(callbacks, request, header_name):
    """
    Attempts to read a header from a request.

    If there are multiple headers in the request, it returns the first. If the header is not present, it raises an exception.

    Args:
        callbacks: the burp callbacks object
        request: the byte[] object that should be parsed.
        header_name: the header that should be retrieved.

    Returns:
        string: the header's value.
    """

def log(message):
    """
    Writes a log to Burp's stdout logging.

    This is a simple wrapper around print in case we want to do something more fancy in the future.

    Args:
        Message to print.
    """
    print(message)
