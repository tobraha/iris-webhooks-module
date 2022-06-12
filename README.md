# IrisWebHooksModule

An interface module that allows to call webhooks from IRIS.   
**Module type** : ``Processor``  
**Min IRIS version required** : ``> 1.4.0`` 

The module is not yet provided with IRIS. It can however be installed manually - please see the Installation section of this readme.

## Configuration 
Please refer to the [IRIS documentation](https://dfir-iris.github.io/operations/modules/natives/IrisWebHooks/). 

## Installation 
The module can be installed manually by running the following command:

1. Get an interactive shell on the docker : ``docker exec -it <iris_web_app> /bin/bash``
2. Install the new package ``pip3 install iris_webhooks_module``
3. Configure the module as explained in the [documentation](https://dfir-iris.github.io/operations/modules/natives/IrisWebHooks/)