#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from abnormalsecurity_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AbnormalSecurityConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AbnormalSecurityConnector, self).__init__()
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._basic_auth_token = None

    def initialize(self):
        """ Automatically called by the BaseConnector before the calls to the handle_action function"""
        config = self.get_config()

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {'Content-Type': 'application/json'}

        # self.set_validator('ipv6', self._is_ip)
        # Base URL
        self._base_url = config[ABNORMAL_JSON_URL_OAuth].rstrip('/')
        self._basic_auth_token = config[ABNORMAL_AUTHORIZATION_TOKEN]

        return phantom.APP_SUCCESS

    def finalize(self):
        return phantom.APP_SUCCESS

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, ABNORMAL_INVALID_INTEGER_MESSAGE.format(param=key)), None

                parameter = int(parameter)
            except Exception as ex:
                return action_result.set_status(phantom.APP_ERROR,
                                                "{}: {}".format(ABNORMAL_INVALID_INTEGER_MESSAGE.format(param=key), self._get_error_message_from_exception(ex))), None

            if key == 'Limit' and parameter == -1:
                return phantom.APP_SUCCESS, parameter
            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, ABNORMAL_INVALID_INTEGER_MESSAGE.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, ABNORMAL_INVALID_INTEGER_MESSAGE.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        if response.status_code == 200 or response.status_code == 202:
            return RetVal(phantom.APP_SUCCESS, "Status code: {}".format(response.status_code))

        return RetVal(action_result.set_status(phantom.APP_ERROR, ABNORMAL_ERR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = ABNORMAL_ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as ex:
            self.debug_print("Error occurred while retrieving exception information: {}".format(self._get_error_message_from_exception(ex)))

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _make_rest_call(self, action_result, endpoint, headers=None, params=None, data=None, json_data=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None
        if not headers:
            headers = {}

        headers.update({
            'Authorization': 'Bearer {0}'.format(self._basic_auth_token)
        })

        if not headers.get('Content-Type'):
            headers['Content-Type'] = 'application/json'

        # Create a URL to connect to
        url = "{0}{1}".format(self._base_url, endpoint)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(url, json=json_data, data=data, headers=headers, params=params)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error connecting to server. Details: {0}".format(self._get_error_message_from_exception(e))), resp_json

        return self._process_response(r, action_result)

    def _hunt_paginator(self, action_result, endpoint, params):
        threats = list()
        api_params = {}
        limit = None
        if params.get('limit'):
            ret_val, limit = self._validate_integer(action_result, params.pop("limit"), "Limit")
            if phantom.is_fail(ret_val):
                return None

        # counts = int(page_size/100) + 1
        # if page_size > 100 and page_size % 100:
        #     page_size = 100
        #     counts += 1
        #     last_page_data = page_size % 100
        # api_params["pageSize"] = page_size
        #
        # for call in range(counts):
        #     ret_val, response = self._make_rest_call(action_result, endpoint, params=api_params)
        #     if phantom.is_fail(ret_val):
        #         return None
        #
        #     if call == counts-1 and response["threats"]:
        #         threats.extend(response["threats"][:last_page_data])
        #         break
        #     threats.extend(response["threats"])
        #
        #     if "nextPageNumber" not in response:
        #         break
        #     api_params["pageNumber"] = response["nextPageNumber"]

        if limit >= 100:
            page_size = 100
        else:
            page_size = limit

        api_params["pageSize"] = page_size
        while True:
            ret_val, response = self._make_rest_call(action_result, endpoint, params=api_params)
            if phantom.is_fail(ret_val):
                return None

            if not response["threats"]:
                return []

            if len(response["threats"]) >= limit:
                threats.extend(response["threats"][:limit])
                return threats

            threats.extend(response["threats"])
            limit -= 100

            if "nextNumber" not in response:
                return threats

            api_params["pageNumber"] = response["nextNumber"]

    def _handle_list_threats(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        threat_list = self._hunt_paginator(action_result, ABNORMAL_GET_THREATS, param)

        if threat_list is None:
            return action_result.get_status()

        if not threat_list:
            return action_result.set_status(phantom.APP_SUCCESS, "No data Found")

        [action_result.add_data(threat) for threat in threat_list]

        return action_result.set_status(phantom.APP_SUCCESS, "Fetched data successfully")

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            param = {}

        param.update({"pageSize": 1})

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(action_result, ABNORMAL_GET_THREATS, params=param)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'list_threats':
            ret_val = self._handle_list_threats(param)

        return ret_val


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = AbnormalSecurityConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AbnormalSecurityConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
