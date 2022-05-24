=========
Pcapyplus
=========

Python extension module to access libpcap.

Pcapyplus is a maintained fork of the no longer maintained pcapy by CORE
Security Technologies available at:

https://github.com/helpsystems/pcapy

In order to support this project the following features were dropped:

- Support for Windows systems.
- Support for Python 2.


Documentation
=============

.. code-block:: sh

    pip3 install tox
    tox -e doc


Install
=======

To install the ``pcapyplus`` package a C++ build system is required, along with
the ``libpcap`` development headers. In Ubuntu systems, run:

.. code-block:: sh

    sudo apt install build-essential libpcap-dev

Finally, install ``pcapyplus`` with:

.. code-block:: sh

    pip3 install pcapyplus


Changelog
=========

1.0.0 (2022-05-19)
------------------

New
~~~

- First stable release.


0.1.0 (2021-02-01)
------------------

New
~~~

- Development preview.


License
=======

::

    Copyright (C) 2021-2022 Hewlett Packard Enterprise Development LP.
    Copyright (C) 2014-2021 CORE Security Technologies

    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
    License for the specific language governing permissions and limitations
    under the License.
