# Benteveo Toolbox.
A burp extension that allows for IDOR testing and facilitates automatic scanning.

To run tests:

```
java -jar ../jython-standalone-2.7.0.jar -Dpython.path=lib/burp-interfaces.jar benteveo_test.py
```

To run an individual test:

```
java -jar ../jython-standalone-2.7.0.jar -Dpython.path=lib/burp-interfaces.jar benteveo_test.py TestToolbox.testRunAllButtonValidState
```

You need the standalone jython from [here](https://www.jython.org/download.html)

# Usage

## Installation

In order to install, clone the repository and then open burp. On the burp Extender page, go to options and set up the "Python environment" category. The only field you need to set up is the one labeled "Location of the Jython standalone JAR file", which should be pointed to the location of `jython-standalone-2.7.0.jar`.

After that, go back to the `Extensions` tab and click `Add`. Set extension type to `Python`, and set the file to the location of `benteveo_toolbox.py`.

## configuration

Once loaded, configuration takes the form of three sections on the `Toolbox > Config` tab.

### Scope section

The first one is the scope section. You should input a URL like `http://www.example.org/subfolder/`, which will match all urls that start with that string. You can input more than one URL, one per line. One that is done, you can click refresh and the `Results` tab will be populated with previously made requests that match the scope.

### Replacement rules

Replacement rules are transformations that are applied to previous requests prior to sending them. For example, you may want to replace a session cookie or a CSRF token.

For example, you may browse the site using an admin user, and then create a replacement rule that will replace their session with a low-level users' cookie.

### Session Check section.

The session check contans a textarea that needs to be populated with a HTTP request that is a good indicator of whether our session is valid or not. It should meet the following preconditions:

1. It should send a 401 or other non 200 OK request when an invalid session is used.
2. It should be affected by our replacement rules, meaning it should have the header we will modify.
3. Once modified with a valid session it should respond with 200 OK.

Once you have populated the field, a user of this application can click the `Check` button. This will obtain your request, modify it as per your replacement rules, and re-send it observing the result. If your session is still valid, the button's label will change to `Check: OK`, whereas if it is no longer valid you will receive a message indicating the reason for this failure.

Clicking the `Run IDOR` button will, if the session check has previously been successful, re-send all requests that have been previously made with the transformation rules applied and store the results.

Clicking the `FUZZ` button will go through requests and, if it is able to find requests whose status code is the same for both the original request and the modified request, send them to Burp's active scan. The idea is to only fuzz one request per endpoint and only initiate fuzzing if we can be reasonable sure we have a valid session for the endpoint.
