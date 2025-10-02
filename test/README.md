### Usage:

- Copy logwisp executable to the test folder (to compile, in logwisp top directory: `make build`).

- Run the test script for each scenario.

### Notes:

- The tests create configuration files and log files. Most tests set logging at debug level and don't clean up their temp files that are created in the current execution directory.

- Some tests may need to be run on different hosts (containers can be used).

