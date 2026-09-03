#!/usr/bin/env python3
# File: infoblox_get_iq_for_td_insights_indicators.py
#
# Copyright (c) 2025-2026 Infoblox Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from urllib.parse import quote

import phantom.app as phantom

import infoblox_consts as consts
from actions import BaseAction


class GetIqForTdInsightsIndicators(BaseAction):
    """Class to handle retrieving IQ for TD insights indicators.

    This action retrieves a filtered list of indicators associated with a specific
    Insight ID from Infoblox, supporting multiple filter parameters.
    """

    def __log_action_start(self):
        """Log the start of the action execution."""
        self._connector.save_progress(consts.EXECUTION_START_MSG.format("Get IQ for TD Insights Indicators"))

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

        # Validate detected_at parameter if provided
        detected_at = self._param.get("detected_at")
        if detected_at:
            if not self._connector.validator.validate_rfc3339_datetime(detected_at):
                return self._action_result.set_status(phantom.APP_ERROR, consts.ERROR_INVALID_RFC3339_DATETIME_FORMAT.format(key="detected_at"))

        # Validate limit parameter if provided
        limit = self._param.get("limit", consts.IQ_FOR_TD_INSIGHTS_DEFAULT_LIMIT)
        if limit is not None:
            ret_val, limit = self._connector.validator.validate_integer(
                self._action_result, limit, "limit", allow_zero=False, allow_negative=False
            )
            if phantom.is_fail(ret_val):
                return ret_val

        return phantom.APP_SUCCESS

    def __make_api_call(self):
        """
        Make the API call to get IQ for TD insights indicators.

        Returns:
            tuple: (status, response) - Status code and API response
        """
        insight_id = quote(str(self._param.get("insight_id")), safe="")
        endpoint = consts.IQ_FOR_TD_INSIGHTS_INDICATORS_ENDPOINT.format(insight_id)

        # Build query parameters
        params = {}

        if self._param.get("indicators"):
            params["indicators"] = self._param.get("indicators")

        if self._param.get("threat_level"):
            params["threat_level"] = self._param.get("threat_level")

        if self._param.get("status"):
            params["status"] = self._param.get("status")

        if self._param.get("users"):
            params["users"] = self._param.get("users")

        if self._param.get("detected_at"):
            params["detected_at"] = self._param.get("detected_at")

        limit = self._param.get("limit", consts.IQ_FOR_TD_INSIGHTS_DEFAULT_LIMIT)
        if limit is not None:
            params["limit"] = limit

        self._connector.debug_print(f"Making API call to get insights indicators for insight ID: {insight_id}")
        self._connector.debug_print(f"Endpoint: {endpoint}")
        self._connector.debug_print(f"Query parameters: {params}")

        return self._connector.util.make_rest_call(endpoint=endpoint, action_result=self._action_result, method="get", params=params)

    def __handle_response(self, response):
        """
        Handle the API response and process the insights indicators data.
        Uses .get() method for safe dictionary access to avoid KeyError exceptions.

        Args:
            response (dict): The API response containing indicators

        Returns:
            int: phantom.APP_SUCCESS on successful processing, phantom.APP_ERROR otherwise
        """
        # Validate response structure using .get() for safe access
        if not isinstance(response, dict):
            return self._action_result.set_status(phantom.APP_ERROR, "Invalid response format: expected JSON object")

        # Check for indicators field (actual API response structure)
        indicators = response.get("indicators")

        if indicators is None:
            self._action_result.add_data({"indicators": []})
            summary = {
                "total_indicators": 0,
            }
            self._action_result.update_summary(summary)
            return self._action_result.set_status(phantom.APP_SUCCESS, "No indicators found for the specified insight ID")

        self._connector.debug_print("Processing insights indicators response")

        # Store complete API response
        self._action_result.add_data(response)

        # Count total indicators
        total_indicators = len(indicators) if isinstance(indicators, list) else 0

        # Generate comprehensive summary
        summary = {
            "total_indicators": total_indicators,
            "insight_id": self._param.get("insight_id", "Unknown"),
            "limit_applied": self._param.get("limit", consts.IQ_FOR_TD_INSIGHTS_DEFAULT_LIMIT),
        }

        self._action_result.update_summary(summary)

        # Set appropriate message
        message = consts.ACTION_GET_INSIGHTS_INDICATORS_SUCCESS_RESPONSE.format(total_indicators)

        return self._action_result.set_status(phantom.APP_SUCCESS, message)

    def execute(self):
        """
        Execute get IQ for TD insights indicators action following the modular approach.

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
        self._connector.save_progress(f"Retrieving indicators for insight ID: {insight_id}")
        ret_val, response = self.__make_api_call()
        if phantom.is_fail(ret_val):
            return ret_val

        # Step 4: Handle response
        ret_val = self.__handle_response(response)
        if phantom.is_fail(ret_val):
            return ret_val

        # Step 5: Return results
        self._connector.save_progress("IQ for TD insights indicators retrieved successfully")
        return phantom.APP_SUCCESS
