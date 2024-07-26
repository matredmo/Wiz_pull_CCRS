# © 2024 Wiz, Inc.
# By using this software and associated documentation files (the “Software”) you hereby agree and understand that:
# 1. The use of the Software is free of charge and may only be used by Wiz customers for its internal purposes.
# 2. The Software should not be distributed to third parties.
# 3. The Software is not part of Wiz’s Services and is not subject to your company’s services agreement with Wiz.
# 4. THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL WIZ BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OF THIS SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Python 3.8+
# pip install -r requirements.txt
import json
import os
import pandas as pd
import base64
import random
import re
import requests
import socket
import sys
import time
import traceback

from datetime import datetime, timezone
from operator import itemgetter
from typing import Any
from yaspin import yaspin

# Start a timer to time the script execution
start_time = datetime.now()

############### Start Script settings ###############
WIZ_CONFIG_PATH = "./wiz_config.json"
# File extension and timestamp are automatically appended
# Final output filename will look like:
# wiz_ccrs-2023-11-01T21:12:57.305002Z.csv
CSV_FNAME = "wiz_ccrs"
############### End Script settings ###############

############### Start Constants ###############
MAX_QUERY_RETRIES = 5
DEFAULT_CLIENT_TIMEOUT = 1800  # 30 mins
BLUE = "\033[94m"
GREEN = "\033[92m"
END = "\033[0m"
SPINNER_COLORS = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
# Script info
SCRIPT_NAME = "Get Wiz Cloud Configuration Rules (CCRs)"
SCRIPT_DESCRIPTION = f"{BLUE}DESCRIPTION:{END}\n  - This script will parse the Wiz CCRs\n  - and write out to a CSV file"
############### End Constants ###############


############### Start Classes ###############
class Timer:
    """
    A class to generate generic timer objects that we use to time function execution
    """

    def __init__(self, text: str):
        self.text = text
        self._start = datetime.now()

    def __str__(self) -> str:
        now = datetime.now()
        delta = now - self._start
        # split the time into minutes:seconds
        total_time = (
            f"{round(delta.total_seconds(),1)}"
            if delta.total_seconds() < 60
            # round rounds down by default, so we include a remainder in the calculation to force
            # a round up in the minutes calculation withouth having to include an additional library
            else f"{round((delta.total_seconds() // 60 + (delta.total_seconds() % 60 > 0)))}_{round((delta.total_seconds()% 60),1)}"
        )
        return f"{self.text} - Total elapsed time: {total_time}s"


class WizClient:
    """
    A class to generate a wiz client thats handle auth and configuration parsing
    """

    def __init__(self, wiz_config_file: str) -> None:
        # Value of wiz_dc is set by _request_api_token function
        self.wiz_dc = ""
        # The headers and header auth formats sent with POST
        self.HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
        self.HEADERS = {"Content-Type": "application/json"}
        # The path of the wiz config file
        self.auth_url, self.client_id, self.client_secret = self._config_parser(
            wiz_config=wiz_config_file
        )
        # Requests a Wiz API token
        # And sets the wiz_dc by inferring the value from the token
        self._request_wiz_api_token(
            auth_url=self.auth_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        self.api_url = f"https://api.{self.wiz_dc}.app.wiz.io/graphql"

    def _pad_base64(self, data: Any) -> Any:
        """
        Internal class method that Ensures that base64 data is padded correctly

        Parameters:
            - data: the base64 data to pad if needed

        Returns:
            - padded: the padded base64 data
        """
        padded = data
        missing_padding = len(padded) % 4
        if missing_padding != 0:
            padded += "=" * (4 - missing_padding)
        return padded

    # @_generic_exception_handler
    def _validate_config(
        self, client_id: str, client_secret: str, auth_url: str
    ) -> None:
        """
        Internal class method that valides the inputs from the config parser
        And exit if any are not

        Parameters:
            - client_id: the wiz client id to check
            - client_secrete: the wiz client secret to check
            - auth_url: the wiz auth url to check

        Returns:
            - none

        """

        # Regex to match us1 - us28, and us28 - 36 (note the ranges we skip)
        auth0_client_matcher = "([a-zA-Z0-9]{32})"
        # 52 or 53 char alphanumeric match for cognito client ids
        cognito_client_matcher = "([a-zA-Z0-9]{52,53})"
        # 64 char alphanumeric match for secret
        secret_matcher = "([A-Za-z0-9-]{64})"

        wiz_auth_endpoints = [
            "https://auth.app.wiz.io/oauth/token",  # Cognito Production
            "https://auth.demo.wiz.io/oauth/token",  # Cognito Demo
            "https://auth.test.wiz.io/oauth/token",  # Cognito Test
            "https://auth.wiz.io/oauth/token",  # Auth0 Production [legacy auth provider]
        ]

        # check to make sure the api url is valid
        if auth_url not in wiz_auth_endpoints:
            sys.exit(
                f"[ERROR] {auth_url} is not a valid Wiz Auth Endpoint. Please check your config file and try again. Exiting..."
            )
        # If we don't find a valid client ID, exit
        if not (
            re.fullmatch(auth0_client_matcher, client_id)
            or re.fullmatch(cognito_client_matcher, client_id)
        ):
            sys.exit(
                f"[ERROR] Did not find a valid Wiz Client ID. Please check your config file and try again. Exiting..."
            )

        # If we dont' find a valid secret, exit
        if not re.fullmatch(secret_matcher, client_secret):
            sys.exit(
                f"[ERROR] Did not find a valid Wiz Secret. Please check your config file and try again. Exiting..."
            )

    # @_generic_exception_handler
    def _config_parser(self, wiz_config: str) -> tuple:
        """
        Internal class method that parses the system for a config file
        OR environment variables for the script to use
        The default behavior is to try a config file first
        And then defer to environment variables

        Parameters:
            - none

        Returns:
            - WIZ_CLIENT_ID: the wiz client id pulled from the config file or the local environment variables
            - WIZ_CLIENT_SECRET: the wiz client secret pulled from the config file or the local environment variables
            - WIZ_AUTH_URL: the wiz client id pulled from the config file or the local environment variables
        """

        try:
            with open(f"{wiz_config}", mode="r") as config_file:
                config = json.load(config_file)

                # Extract the values from our dict and assign to vars
                wiz_auth_url, wiz_client_id, wiz_client_secret = itemgetter(
                    "wiz_auth_url", "wiz_client_id", "wiz_client_secret"
                )(config)

                # Validate the inputs and get the current Wiz DC back
                self._validate_config(
                    client_id=wiz_client_id,
                    client_secret=wiz_client_secret,
                    auth_url=wiz_auth_url,
                )

        except FileNotFoundError:
            pass

            try:
                wiz_client_id = str(os.getenv("wiz_client_id"))
                wiz_client_secret = str(os.getenv("wiz_client_secret"))
                wiz_auth_url = str(os.getenv("wiz_auth_url"))

                # Validate the inputs and get the current Wiz DC back
                self._validate_config(
                    client_id=wiz_client_id,
                    client_secret=wiz_client_secret,
                    auth_url=wiz_auth_url,
                )

            except Exception:
                sys.exit(
                    f"[ERROR] Unable to find one or more Wiz environment variables. Please check them and try again."
                )

        return (
            wiz_auth_url,
            wiz_client_id,
            wiz_client_secret,
        )

    # @_generic_exception_handler
    def _request_wiz_api_token(
        self, auth_url: str, client_id: str, client_secret: str
    ) -> None:
        """
        Request a token to be used to authenticate against the wiz API

        Parameters:
            - client_id: the wiz client ID
            - client_secret: the wiz secret

        Returns:
            - TOKEN: A session token
        """
        audience = (
            "wiz-api"
            if "auth.app" in auth_url or "auth.gov" in auth_url
            else "beyond-api"
        )

        auth_payload = {
            "grant_type": "client_credentials",
            "audience": audience,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        # Initliaze a timer
        func_time = Timer("+ Requesting Wiz API token")

        with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
            # Request token from the Wiz API
            response = requests.post(
                url=auth_url,
                headers=self.HEADERS_AUTH,
                data=auth_payload,
                timeout=DEFAULT_CLIENT_TIMEOUT,
                # timeout=None,
            )

            if response.status_code != requests.codes.ok:
                raise Exception(
                    f"Error authenticating to Wiz {response.status_code} - {response.text}"
                )

            try:
                response_json = response.json()
                TOKEN = response_json.get("access_token")
                if not TOKEN:
                    message = "Could not retrieve token from Wiz: {}".format(
                        response_json.get("message")
                    )
                    raise Exception(message)
            except ValueError as exception:
                print(exception)
                raise Exception("Could not parse API response")
            self.HEADERS["Authorization"] = "Bearer " + TOKEN

            response_json_decoded = json.loads(
                base64.standard_b64decode(self._pad_base64(TOKEN.split(".")[1]))
            )

            self.wiz_dc = response_json_decoded["dc"]


############### End Classes ###############


############### Start Queries and Vars ###############
cloud_config_rules_query = """
query CloudConfigurationSettingsTable(
    $first: Int
    $after: String
    $filterBy: CloudConfigurationRuleFilters
    $orderBy: CloudConfigurationRuleOrder
    $projectId: [String!]
  ) {
    cloudConfigurationRules(
      first: $first
      after: $after
      filterBy: $filterBy
      orderBy: $orderBy
    ) {
      analyticsUpdatedAt
      nodes {
        id
        shortId
        name
        description
        enabled
        severity
        serviceType
        cloudProvider
        subjectEntityType
        functionAsControl
        builtin
        targetNativeTypes
        remediationInstructions
        hasAutoRemediation
        supportsNRT
        createdAt
        updatedAt
        control {
          id
        }
        analytics(selection: { projectId: $projectId }) {
          passCount
          failCount
        }
        scopeAccounts {
          id
        }
        securitySubCategories {
        id
        title
        description
        category {
          id
          name
          description
          framework {
            id
            name
            enabled
          }
        }
      }
      }
      pageInfo {
        endCursor
        hasNextPage
      }
      totalCount
    }
  }
"""

cloud_config_rules_query_vars = {
    "first": 500,
    "orderBy": {"field": "FAILED_CHECK_COUNT", "direction": "DESC"},
     "filterBy": {
     "cloudProvider" : "AWS",
     "frameworkCategory": [
      "wf-id-13"
     ]
}}

############### End Queries and Vars ###############


############### Start Functions ###############
def _generic_exception_handler(function: Any) -> Any:
    """
    Private decorator function for error handling

    Parameters:
        - function: the function to pass in

    Returns:
        - _inner_function: the decorated function
    """

    def _inner_function(*args: Any, **kwargs: Any) -> Any:
        try:
            function_result = function(*args, **kwargs)
            return function_result
        except ValueError as v_err:
            print(traceback.format_exc(), f"{v_err}")
            sys.exit(1)
        except Exception as err:
            if (
                "502: Bad Gateway" not in str(err)
                and "503: Service Unavailable" not in str(err)
                and "504: Gateway Timeout" not in str(err)
            ):
                print(traceback.format_exc(), f"[ERROR]: {err}")
                return err

            else:
                print(traceback.format_exc(), "[ERROR] - Retry")

            sys.exit(1)

    return _inner_function


def print_logo(client: WizClient) -> None:
    """
    Print out the Wiz logo and script information

    Parameters:
        - none

    Returns:
        - none
    """

    print(
        f"""
                    __      _(_)____   ✦  ✦                                 
                    \ \ /\ / / |_  /     ✦                                  
                     \ V  V /| |/ /                                           
                      \_/\_/ |_/___|  © 2024 Wiz, Inc. 
+----------------------------------------------------------------------+
  WIZ DATACENTER: {BLUE}{client.wiz_dc}{END}
  API URL: {BLUE}{client.api_url}{END}
  AUTH URL: {BLUE}{client.auth_url}{END} 
+----------------------------------------------------------------------+
  SCRIPT NAME: {BLUE}{SCRIPT_NAME}{END}
+----------------------------------------------------------------------+
  {SCRIPT_DESCRIPTION}
+----------------------------------------------------------------------+
  OUTPUT CSV: {BLUE}{CSV_FNAME}-<timestamp>.csv{END}
+----------------------------------------------------------------------+"""
    )


@_generic_exception_handler
def query_wiz_api(client: WizClient, query: str, variables: dict) -> dict:
    """
    Query the WIZ API for the given query data schema
    Parameters:
        - query: the query or mutation we want to run
        - variables: the variables to be passed with the query or mutation
    Returns:
        - result: a json representation of the request object
    """

    # Init counters for retries, backoff
    retries = 0
    backoff = 1

    response = requests.post(
        url=client.api_url,
        json={"variables": variables, "query": query},
        headers=client.HEADERS,
    )

    code = response.status_code

    # Handle retries, and exponential backoff logic
    while code != requests.codes.ok:
        # Increment backoff counter
        # Retries look like 1, 2, 4, 16, 32
        backoff = backoff * 2
        if retries >= MAX_QUERY_RETRIES:
            raise Exception(
                f"[ERROR] Exceeded the maximum number of retries [{response.status_code}] - {response.text}"
            )

        if code == requests.codes.unauthorized or code == requests.codes.forbidden:
            raise Exception(
                f"[ERROR] Authenticating to Wiz [{response.status_code}] - {response.text}"
            )
        if code == requests.codes.not_found:
            raise Exception(f"[ERROR] Unknown error [{response.status_code}]")

        if backoff != 0:
            print(f"\n└─ Backoff triggered, waiting {backoff}s and retrying.")

        time.sleep(backoff)

        response = requests.post(
            url=client.api_url,
            json={"variables": variables, "query": query},
            headers=client.HEADERS,
        )
        code = response.status_code
        retries += 1

    # Catch edge case where we get a valid response but empty response body
    if not response:
        time.sleep(backoff)
        response = requests.post(
            url=client.api_url,
            json={"variables": variables, "query": query},
            headers=client.HEADERS,
        )
        raise Exception(f"\n API returned no data or emtpy data set. Retrying.")

    response_json = response.json()

    if response_json.get("errors"):
        errors = response_json.get("errors")[0]
        raise Exception(
            f'\n └─ MESSAGE: {errors["message"]}, \n └─ CODE: {errors["extensions"]["code"]}'
        )

    if response_json.get("code") == "DOWNSTREAM_SERVICE_ERROR":
        errors = response_json.get("errors")
        request_id = errors["message"].partition("request id: ")[2]

        raise Exception(
            f"[ERROR] - DOWNSTREAM_SERVICE_ERROR - request id: {request_id}"
        )

    return response_json


@_generic_exception_handler
def get_api_result(client: WizClient) -> pd.DataFrame:
    """
    A wrapper around the query_wiz_api function
    That fetches the cloud controls for the tenant

    Parameters:
        - none

    Returns:
        - df: a pandas dataframe
    """

    # Initliaze a timer
    func_time = Timer("+ Fetching CCRs from Wiz")

    with yaspin(text=func_time, color="white"):
        # Query the wiz API
        result = query_wiz_api(
            client=client,
            query=cloud_config_rules_query,
            variables=cloud_config_rules_query_vars,
        )

        # Get the unique query key for the query
        query_key = str(list(result["data"].keys())[0])

        df = pd.json_normalize(
            result["data"][query_key]["nodes"], sep="_", errors="ignore"
        )

        page_info = result["data"][query_key]["pageInfo"]

        # Count starting at 1 because we always sent at least 1 page
        page_count = 1

        # Continue querying until we have no pages left
        while page_info["hasNextPage"]:
            # Increment page count with each page
            page_count += 1

            # Advance the cursor
            cloud_config_rules_query_vars["after"] = page_info["endCursor"]

            # Query the API, now with a new after value
            result = query_wiz_api(
                client=client,
                query=cloud_config_rules_query,
                variables=cloud_config_rules_query_vars,
            )

            df = pd.concat(
                [
                    df,
                    pd.json_normalize(
                        result["data"][query_key]["nodes"], sep="_", errors="ignore"
                    ),
                ]
            )

            page_info = result["data"][query_key]["pageInfo"]

    print(
        func_time,
        f'\n└─ DONE: Got {GREEN}{page_count}{END} pages containing {GREEN}{result["data"][query_key]["totalCount"]}{END} results',
    )

    return df


############### End Functions ###############


def main() -> None:
    # Build a wiz client
    wiz_client = WizClient(wiz_config_file=WIZ_CONFIG_PATH)
    # Print the wiz logo and script info
    print_logo(client=wiz_client)

    df = get_api_result(client=wiz_client)

    # Get timezone information in UTC
    timestamp_now = f"{datetime.now(timezone.utc)}Z".replace(" ", "T").replace(
        "+00:00", ""
    )

    timestamped_fname = f"{CSV_FNAME}-{timestamp_now.replace(':', '-')}.csv"

    func_time = Timer(f"+ Writing results to file")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # any columns you want to exclude from the CSV
        # df.loc[:, df.columns != ""]
        df.to_csv(timestamped_fname, encoding="utf-8")

    print(
        func_time,
        f"\n└─ DONE: Wrote data to file:\n└── {GREEN}{timestamped_fname}{END}",
    )

    end_time = datetime.now()

    total_elapsed_time = (
        f"{round((end_time - start_time).total_seconds(),1)}"
        if (end_time - start_time).total_seconds() < 60
        # round rounds down by default, so we include a remainder in the calculation to force
        # a round up in the minutes calculation withouth having to include an additional library
        else f"{round(((end_time - start_time).total_seconds() // 60 + ((end_time - start_time).total_seconds()% 60 > 0)))}:{round(((end_time - start_time).total_seconds()% 60),1)}"
    )

    print(f"+ Script Finished\n└─ Total script elapsed time: {total_elapsed_time}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n+ Ctrl+C interrupt received. Exiting.")
        pass
