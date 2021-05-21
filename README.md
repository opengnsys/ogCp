# ogCP

ogCP (OpenGnsys Control Panel) is the new web interface, a modern alternative
to the classical administration panel (WebConsole).

## Installation

Steps to install ogCP on Ubuntu 18.04 LTS:

* Clone the repository that is temporarily available at:
https://github.com/javsanpar/ogCP
* Edit `ogcp/cfg/ogcp.json` and include the API token and the IP address of
the ogServer. In addition, we must define the user and the key we want for
authentication in ogCP.
* Create a python virtual environment.
    * Install venv with:
        ```bash
        apt-get install python3-venv
        ```
    * Create the folder where we will start the virtual environment.
    * Create the virtual environment with:
        ```bash
        python3 -m venv ./previous-folder
        ```
* Activate the shell with the virtual environment with:
    ```bash
    source ./previous-folder/bin/activate
    ```
* (Optional) If you want to expose ogCP to other machines, you must edit
`run_test.sh` with:
    ```bash
    ...
    flask run --host=0.0.0.0
    ```
* With the shell linked to the newly created python environment, navigate to
the folder where you cloned ogCP and launch:
    ```bash
    ./run_test.sh
    ```
  When running `run_test.sh` for the first time some errors are expected, but
  they do not affect to the usability of ogCP.

## License

ogCP is released under the GNU Affero Public License v3+

## Authors

[Soleta Networks](https://opengnsys.soleta.eu)
