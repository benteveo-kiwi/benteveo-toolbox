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
