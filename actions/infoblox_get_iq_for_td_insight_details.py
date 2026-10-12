# File: infoblox_get_iq_for_td_insight_details.py
#
# Copyright 2026 Infoblox Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from urllib.parse import quote

import phantom.app as phantom

import infoblox_consts as consts
from actions import BaseAction


class GetIqForTdInsightDetails(BaseAction):
    """Class to handle get iq for td insight details action.

    This action retrieves the full detail view for a single IQ for TD Insight from Infoblox,
    including counts, severity, top indicators/assets, threat actors, and recommendations.
    """

    def _validate_params(self):
        """
        Validate action parameters for format/content.
        Note: Required parameter validation is handled by SOAR's built-in JSON schema validation.

        Returns:
            int: phantom.APP_SUCCESS if validation passes, phantom.APP_ERROR otherwise
        """
        ret_val = self._connector.validator.validate_path_identifier(self._action_result, self._param.get("insight_id"), "insight_id")
        if phantom.is_fail(ret_val):
            return ret_val

        return phantom.APP_SUCCESS

    def __log_action_start(self):
        """Log the start of the action execution."""
        self._connector.save_progress(consts.EXECUTION_START_MSG.format("Get IQ for TD Insight Details"))

    def __make_api_call(self):
        """
        Make the API call to retrieve the insight details.

        Returns:
            tuple: (status, response) - Status code and API response
        """
        insight_id = self._param.get("insight_id")
        endpoint = consts.IQ_FOR_TD_INSIGHT_DETAILS_ENDPOINT.format(quote(str(insight_id), safe=""))

        self._connector.debug_print(f"Making API call to get iq for td insight details for insight ID: {insight_id}")
        self._connector.debug_print(f"Endpoint: {endpoint}")

        return self._connector.util.make_rest_call(endpoint=endpoint, action_result=self._action_result, method="get")

    def __handle_response(self, response):
        """
        Handle the API response and process the insight details data.

        Args:
            response (dict): The API response containing insight details

        Returns:
            int: phantom.APP_SUCCESS on successful processing, phantom.APP_ERROR otherwise
        """
        if not isinstance(response, dict):
            return self._action_result.set_status(phantom.APP_ERROR, "Invalid response format: expected JSON object")

        self._connector.debug_print("Processing insight details response")

        # Store the complete API response unchanged. View-only presentation
        # filtering is handled by display_get_iq_for_td_insight_details.
        self._action_result.add_data(response)

        # Generate summary from key fields
        summary = {
            "insight_id": response.get("insight_id", self._param.get("insight_id", "Unknown")),
            "status": response.get("status"),
            "severity": response.get("severity"),
            "total_events": response.get("total_events"),
            "total_indicators": response.get("total_indicators"),
            "total_assets": response.get("total_assets"),
            "total_users": response.get("total_users"),
        }
        self._action_result.update_summary(summary)

        message = consts.ACTION_GET_INSIGHT_DETAILS_SUCCESS_RESPONSE.format(insight_id=summary["insight_id"])

        return self._action_result.set_status(phantom.APP_SUCCESS, message)

    def execute(self):
        """
        Execute get iq for td insight details action following the modular approach.

        Step 1: Log action start
        Step 2: Validate parameters
        Step 3: Make API call
        Step 4: Handle response

        Returns:
            int: phantom.APP_SUCCESS on successful execution, phantom.APP_ERROR otherwise
        """
        # Step 1: Log action start
        self.__log_action_start()

        # Step 2: Validate parameters (format/content only, required validation handled by SOAR)
        self._connector.save_progress("Validating parameters")
        ret_val = self._validate_params()
        if phantom.is_fail(ret_val):
            return ret_val

        # Step 3: Make API call
        insight_id = self._param.get("insight_id")
        self._connector.save_progress(f"Retrieving details for insight ID: {insight_id}")
        ret_val, response = self.__make_api_call()
        if phantom.is_fail(ret_val):
            return ret_val

        # Step 4: Handle response
        ret_val = self.__handle_response(response)
        if phantom.is_fail(ret_val):
            return ret_val

        # Step 5: Return results
        self._connector.save_progress("Insight details retrieved successfully")
        return phantom.APP_SUCCESS
