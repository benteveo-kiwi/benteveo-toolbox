
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
