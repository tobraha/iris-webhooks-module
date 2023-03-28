#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2022 - DFIR-IRIS Team
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import json
import requests

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes
from app.datamgmt.iris_engine.modules_db import module_list_available_hooks

import iris_webhooks_module.IrisWebHooksConfig as interface_conf


class IrisWebHooksInterface(IrisModuleInterface):
    """
    Provide the interface between Iris and WebHooks
    """
    name = "IrisWebHooksInterface"
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):
        """
        Registers hooks for the module. None by default

        :param module_id: Module ID provided by IRIS
        :return: Nothing
        """
        self.module_id = module_id
        module_conf = self.module_dict_conf

        if module_conf is None:
            self.log.info('No configuration found - probably first run')
            return

        hooks = []

        if module_conf.get('wh_configuration') is None:
            self.log.info('Web hook configuration not found. Maybe first run?')
            self.log.info('Nothing to do here')
            return

        jconfig = json.loads(module_conf.get('wh_configuration'))

        if not jconfig.get('webhooks'):
            self.log.info('No web hooks configured - skipping')
            return

        if not self._check_self_config(jconfig.get('webhooks')):
            self.log.error('Web hook configuration not valid')
            return

        available_hooks = [hook.hook_name for hook in module_list_available_hooks()]
        for inhook in available_hooks:
            if 'on_postload' not in inhook:
                continue
            self.deregister_from_hook(module_id=module_id, iris_hook_name=inhook)

        for hook in jconfig.get('webhooks'):

            for iris_hook in hook.get('trigger_on'):

                if hook.get('active') is False:
                    self.log.info(f'Web hook {hook.get("name")} is not active, skipping')
                    continue

                if iris_hook in ['all', 'all_update', 'all_create', 'all_delete']:
                    hook_split = iris_hook.split('_')
                    hook_action = None

                    if len(hook_split) == 2:
                        hook_action = hook_split[1]

                    for inhook in available_hooks:
                        if 'on_postload' not in inhook:
                            continue

                        if hook_action and not inhook.endswith(hook_action):
                            continue

                        self.log.info(f'Registering to {inhook}')
                        status = self.register_to_hook(module_id, iris_hook_name=inhook)
                        if status.is_failure():
                            self.log.error(status.get_message())
                            self.log.error(status.get_data())

                        else:
                            hooks.append(inhook)

                if 'on_postload' not in iris_hook:
                    self.log.warning(f'{iris_hook} is not supported by this module')
                    continue

                self.log.info(f'Registering to {iris_hook}')
                status = self.register_to_hook(module_id, iris_hook_name=iris_hook)

                if status.is_failure():
                    self.log.error(status.get_message())
                    self.log.error(status.get_data())

                else:
                    hooks.append(iris_hook)

        self.log.info('Successfully registered to hooks {hooks}'.format(hooks=','.join(set(hooks))))

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
        """
        Hooks handler table. Calls corresponding methods depending on the hooks name.

        :param hook_name: Name of the hook which triggered
        :param hook_ui_name: Name of the ui hook
        :param data: Data associated with the trigger.
        :return: Data
        """

        self.log.info(f'Received {hook_name}')
        status = self._handle_hook(hook_name, hook_ui_name, data=data)

        if status.is_failure():
            self.log.error(f"Encountered error processing hook {hook_name}")
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        self.log.info(f"Successfully processed hook {hook_name}")
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))

    def _handle_hook(self, hook_name, hook_ui_name, data) -> InterfaceStatus.IIStatus:
        """
        Handle the data the module just received. The module registered
        to on_postload hooks, so it receives instances of object.
        These objects are attached to a dedicated SQlAlchemy session so data can
        be modified safely.

        :param data: Data associated to the hook
        :param hook_name: Name of the received hook
        :param hook_ui_name: Name of the hook in UI
        :return: IIStatus
        """

        self.log.info(f'Received {hook_name}, {hook_ui_name}')
        in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

        module_conf = self.module_dict_conf

        if module_conf.get('wh_configuration') is None:
            self.log.error('Web hook configuration not found')

        jconfig = json.loads(module_conf.get('wh_configuration'))
        if not self._check_self_config(jconfig.get('webhooks')):
            self.log.error('Web hook configuration not valid')
            return InterfaceStatus.I2Error(msg='Configuration not valid')

        server_url = jconfig.get('instance_url')

        for hook in jconfig.get('webhooks'):

            for iris_hook in hook.get('trigger_on'):
                if hook.get('active') is False:
                    self.log.info(f'Web hook {hook.get("name")} is not active, skipping')
                    continue

                if iris_hook in ['all', 'all_update', 'all_create']:
                    hook_split = iris_hook.split('_')

                    if len(hook_split) == 2:
                        hook_action = hook_split[1]

                        if hook_name.endswith(hook_action):
                            self._do_web_hook(hook_name, data, hook, server_url)

                    else:
                        self._do_web_hook(hook_name, data, hook, server_url)

                elif iris_hook == hook_name:

                    self._do_web_hook(hook_name, data, hook, server_url)

        return in_status(data=data)

    def _do_web_hook(self, hook_name, data, hook, server_url) -> InterfaceStatus.IIStatus:
        """

        :param hook_name:
        :param server_url:
        :param data:
        :param hook:
        :param server_url:
        :return:
        """

        hook_split = hook_name.split('_')
        hook_type = hook_split[-1]
        hook_object = '_'.join(hook_split[2:-1])

        user_name = 'N/A'
        object_name = 'N/A'
        case_name = 'N/A'
        case_id = None
        object_url = None
        case_info = ""

        request_rendering = hook.get('request_rendering')

        if hook_object == 'case':
            user_name = data[0].user.name
            object_name = data[0].name
            object_url = f"{server_url}/case?cid={data[0].case_id}"
            case_name = data[0].name

        elif hook_object == 'asset':
            user_name = data[0].user.name
            object_name = data[0].asset_name
            case_id = data[0].case_id
            object_url = f"{server_url}/case/assets?cid={case_id}&shared={data[0].asset_id}"
            case_name = data[0].case.name

        elif hook_object == 'note':
            user_name = data[0].user.name
            object_name = data[0].note_title
            case_id = data[0].note_case_id
            object_url = f"{server_url}/case/notes?cid={case_id}&shared={data[0].note_id}"
            case_name = data[0].case.name

        elif hook_object == 'ioc':
            user_name = data[0].user.name
            object_name = data[0].ioc_value

        elif hook_object == 'event':
            user_name = data[0].user.name
            object_name = data[0].event_title
            case_name = data[0].case.name
            case_id = data[0].case_id
            object_url = f"{server_url}/case/timeline?cid={case_id}&shared={data[0].event_id}"

        elif hook_object == 'evidence':
            user_name = data[0].user.name
            object_name = data[0].filename
            case_name = data[0].case.name
            case_id = data[0].case_id
            object_url = f"{server_url}/case/evidences?cid={case_id}&shared={data[0].id}"

        elif hook_object == 'task':
            user_name = data[0].user_update.name
            object_name = data[0].task_title
            case_name = data[0].case.name
            case_id = data[0].task_case_id
            object_url = f"{server_url}/case/task?cid={case_id}&shared={data[0].id}"

        elif hook_object == 'global_task':
            user_name = data[0].user_update.name
            object_name = data[0].task_title
            case_name = 'Global'
            case_id = None
            object_url = f"{server_url}/dashboard?cid=1#gtasks_table_wrapper"

        elif hook_object == 'report':
            object_name = 'a report'

        if object_url:
            object_name = self._render_url(object_url, object_name, request_rendering)

        if case_id:
            case_info = "on case {rendered_url}".format(
                rendered_url=self._render_url(f"{server_url}/case?cid={case_id}",
                                              f"#{case_id}", request_rendering))
        else:
            case_info = ""

        description = f"{user_name} {hook_type}d {hook_object} {object_name} {case_info}"
        title = f"[{case_name}] {hook_object.capitalize()} {hook_type}d"

        try:
            request_content = json.dumps(hook.get('request_body'))
        except Exception as e:
            self.log.error(str(e))
            return

        request_content = request_content.replace('%TITLE%', title)
        request_content = request_content.replace('%DESCRIPTION%', description)

        try:
            request_data = json.loads(request_content)
        except Exception as e:
            self.log.error(str(e))
            return

        url = hook.get('request_url')

        result = requests.post(url, json=request_data)

        try:
            result.raise_for_status()
        except requests.exceptions.HTTPError as err:
            self.log.error(err)
        else:
            self.log.info(f"Webhook {hook.get('name')} - Payload delivered successfully, code {result.status_code}.")

    def _render_url(self, url, link, rendering_format):
        """
        Renders the url with the rendering format
        :param url: url to render
        :param link: link to render
        :param rendering_format: rendering format
        :return: rendered url
        """

        if rendering_format == 'markdown':
            return f"[{link}]({url})"
        elif rendering_format == 'markdown_slack':
            return f"<{url}|{link}>"
        elif rendering_format == 'html':
            return f"<a href='{url}'>{link}</a>"
        else:
            return url

    def _check_self_config(self, jconfig):
        """
        Verifies the web hook configuration provided is valid
        :return: Bool
        """

        for hook in jconfig:

            if hook.get('name') is None:
                self.log.error('Tag "name" not found in web hook configuration')
                return False

            if hook.get('request_url') is None:
                self.log.error('Tag "request_url" not found in web hook configuration')
                return False

            if hook.get('request_body') is None:
                self.log.error('Tag "request_body" not found in web hook configuration')
                return False

            if hook.get('trigger_on') is None:
                self.log.error('Tag "trigger_on" not found in web hook configuration')
                return False

        return True
