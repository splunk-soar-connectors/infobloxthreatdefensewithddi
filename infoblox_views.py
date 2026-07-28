# File: infoblox_views.py
#
# Copyright 2025-2026 Infoblox Inc.
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


def _is_recommendation_action_taken(recommendation):
    """Coerce a recommendation's action_taken value to a bool.

    The API returns this field as a string ("true"/"false"), not a JSON boolean.
    """
    value = recommendation.get("action_taken")
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _coerce_to_list(value):
    """Return value as a list of non-empty items.

    The insight details API returns ``threat_properties`` and ``overview`` as
    lists, but this guards against a scalar/string being returned so the
    template can always iterate.

    Args:
        value: The raw field value (list, string, or None)

    Returns:
        list: A list of non-empty items
    """
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    if value in (None, ""):
        return []
    return [value]


def display_indicator_threat_data(provides, all_app_runs, context):
    """
    Display Indicator Threat Data

    This function renders a simple view for the Infoblox threat intelligence data
    obtained from the indicator_threat_lookup action.

    Args:
        provides (str): The name of the action that provides the data
        all_app_runs (list): List of all app runs
        context (dict): Context to render the template with

    Returns:
        str: The path to the HTML template to render
    """
    context["results"] = {}
    context["has_data"] = False

    for _, action_results in all_app_runs:
        for result in action_results:
            # Get the raw data from the action result
            data = result.get_data()
            if not data:
                continue

            context["has_data"] = True

            # Process the threat data
            all_threats = []

            for item in data:
                if "threat" in item:
                    for threat in item["threat"]:
                        all_threats.append(threat)

            # Add all threats to the context
            context["results"] = {"all": all_threats}
            context["total_threats"] = len(all_threats)

            # Get the search parameters
            context["indicator_type"] = result.get_param().get("indicator_type", "All")
            context["indicator_value"] = result.get_param().get("indicator_value", "")

    return "views/infoblox_indicator_threat_lookup.html"


def display_initiate_indicator_intel_lookup(provides, all_app_runs, context):
    """
    Display Initiate Indicator Intel Lookup Data

    This function renders a custom view for the Infoblox initiate indicator intel lookup action.
    When wait_for_results is false, it displays just the job status and ID.
    When wait_for_results is true, it displays the full result table.

    Args:
        provides (str): The name of the action that provides the data
        all_app_runs (list): List of all app runs
        context (dict): Context to render the template with

    Returns:
        str: The path to the HTML template to render
    """
    context["has_data"] = False
    context["results"] = []
    context["wait_for_results"] = "false"  # Default value
    context["job_id"] = ""
    context["status"] = ""
    context["total_results"] = 0
    context["indicator_type"] = ""
    context["indicator_value"] = ""
    context["source"] = ""

    for _, action_results in all_app_runs:
        for result in action_results:
            # Get the raw data from the action result
            data = result.get_data()
            if not data:
                continue

            context["has_data"] = True

            # Get the first data item
            data_item = data[0]

            # Extract job information
            context["job_id"] = data_item.get("job_id", "")
            context["status"] = data_item.get("status", "")

            # Get the wait_for_results parameter
            wait_for_results = result.get_param().get("wait_for_results", "false").lower()
            context["wait_for_results"] = wait_for_results

            # Get indicator details
            context["indicator_type"] = result.get_param().get("indicator_type", "")
            context["indicator_value"] = result.get_param().get("indicator_value", "")
            context["source"] = result.get_param().get("source", "")

            # If wait_for_results is true, process results
            if wait_for_results == "true" and data_item.get("results"):
                # Get the results list if available
                results = data_item.get("results", [])
                context["results"] = results
                context["total_results"] = len(results)

    return "views/infoblox_initiate_indicator_intel_lookup.html"


def display_get_iq_for_td_insight_details(provides, all_app_runs, context):
    """
    Display Get IQ for TD Insight Details Data

    This function renders a custom detail view for the get_iq_for_td_insight_details action,
    breaking the single insight object out into an overview panel plus dedicated
    sections for top indicators, top assets, threat actors, and key recommendations.

    Args:
        provides (str): The name of the action that provides the data
        all_app_runs (list): List of all app runs
        context (dict): Context to render the template with

    Returns:
        str: The path to the HTML template to render
    """
    context["has_data"] = False
    context["insight"] = {}

    for _, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            if not data:
                continue

            context["has_data"] = True
            insight = dict(data[0])
            key_recommendations = insight.get("key_recommendations")
            if isinstance(key_recommendations, list):
                insight["key_recommendations"] = [rec for rec in key_recommendations if not _is_recommendation_action_taken(rec)]
            # Normalize list-valued fields so the template can render them as
            # tags/bullets instead of a raw Python list repr.
            insight["threat_properties"] = _coerce_to_list(insight.get("threat_properties"))
            insight["overview"] = _coerce_to_list(insight.get("overview"))
            context["insight"] = insight

    return "views/infoblox_get_iq_for_td_insight_details.html"
