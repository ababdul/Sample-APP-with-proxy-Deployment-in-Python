"""
Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, 
provided that you agree: 
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and 
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
including attorneys’ fees, that arise or result from the use or distribution of the Sample Code    
"""
 
import os
import json
import logging
from typing import Any, Dict, Optional
import requests
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient


# Configuration keys expected in Function App settings (local.settings.json for local testing)
# SERVICE_NOW_INSTANCE: e.g. https://devXXXX.service-now.com
# SERVICE_NOW_TABLE: e.g. incident or sc_request (default: incident)
# SERVICE_NOW_USER & SERVICE_NOW_PASSWORD    -> for Basic Auth
# SERVICE_NOW_TOKEN -> Optional: Bearer token string. If present, used instead of Basic Auth
# PROXY_URL -> e.g. http://proxy.company.com:8080
# PROXY_USERNAME & PROXY_PASSWORD -> Optional: credentials for proxy
# PROXY_VERIFY -> 'false' to disable SSL verification for outbound call (not recommended)


def _get_secret_from_keyvault(secret_name: str) -> Optional[str]:
    """Retrieve a secret value from Key Vault using DefaultAzureCredential.
    Environment variables expected:
      - KEY_VAULT_URL: the full URL of the key vault (e.g. https://mykv.vault.azure.net/)
    """
    kv_url = os.getenv("KEY_VAULT_URL")
    if not kv_url:
        logging.warning("KEY_VAULT_URL not set; cannot retrieve secret '%s' from Key Vault", secret_name)
        return None

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=kv_url, credential=credential)
        secret = client.get_secret(secret_name)
        return secret.value
    except Exception:
        logging.exception("Failed to retrieve secret %s from Key Vault", secret_name)
        return None


def _build_proxies() -> Optional[Dict[str, str]]:
    proxy_url = os.getenv("PROXY_URL")
    if not proxy_url:
        return None

    proxy_username = os.getenv("PROXY_USERNAME")
    proxy_password = os.getenv("PROXY_PASSWORD")

    # If a password is not present in env vars, try to fetch it from Key Vault
    if not proxy_password:
        # Accept either PROXY_PASSWORD_SECRET_NAME or PROXY_PASSWORD_SECRET to be flexible
        secret_name = os.getenv("PROXY_PASSWORD_SECRET_NAME") or os.getenv("PROXY_PASSWORD_SECRET")
        if secret_name:
            proxy_password = _get_secret_from_keyvault(secret_name)

    # If proxy credentials are provided, embed them into the proxy URL
    if proxy_username and proxy_password:
        # If the proxy_url already contains scheme, remove any preceding // to avoid double
        if proxy_url.startswith("http://") or proxy_url.startswith("https://"):
            scheme, rest = proxy_url.split("://", 1)
            proxy_with_creds = f"{scheme}://{proxy_username}:{proxy_password}@{rest}"
        else:
            proxy_with_creds = f"http://{proxy_username}:{proxy_password}@{proxy_url}"
    else:
        proxy_with_creds = proxy_url

    return {"http": proxy_with_creds, "https": proxy_with_creds}


def _get_auth_headers() -> Dict[str, str]:
    token = os.getenv("SERVICE_NOW_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    # otherwise Basic Auth will be used by requests itself (return empty headers)
    return {"Content-Type": "application/json"}


def _get_basic_auth():
    user = os.getenv("SERVICE_NOW_USER")
    pwd = os.getenv("SERVICE_NOW_PASSWORD")

    # If not present in environment, try Key Vault using provided secret names
    if not user:
        snowUser_secret_name = os.getenv("SERVICE_NOW_USER_SECRET_NAME") or os.getenv("SERVICE_NOW_USER_SECRET")
        if snowUser_secret_name:
            user = _get_secret_from_keyvault(snowUser_secret_name)

    if not pwd:
        snowPwd_secret_name = os.getenv("SERVICE_NOW_PASSWORD_SECRET_NAME") or os.getenv("SERVICE_NOW_PASSWORD_SECRET")
        if snowPwd_secret_name:
            pwd = _get_secret_from_keyvault(snowPwd_secret_name)

    if user and pwd:
        return (user, pwd)
    return None


def _build_servicenow_url(table: str) -> str:
    instance = os.getenv("SERVICE_NOW_INSTANCE")
    if not instance:
        raise ValueError("Missing required environment variable: SERVICE_NOW_INSTANCE")

    # Allow either a full API endpoint or an instance base URL
    # If user provided a full endpoint (contains /api/), use it directly
    if "/api/" in instance:
        base = instance.rstrip("/")
    else:
        base = instance.rstrip("/") + "/api/now/table"

    # If the instance already includes the table, avoid duplicating
    if base.endswith(f"/{table}"):
        return base

    return f"{base}/{table}"


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("ServiceNow proxy function triggered")

    try:
        req_body = req.get_json()
    except ValueError:
        # invalid JSON
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON in request body"}), status_code=400, mimetype="application/json"
        )

    # If a Logic App sends a wrapper payload, it can include a 'servicenow_payload' field
    # Otherwise, the Function will forward the entire JSON body as the ServiceNow payload
    payload = req_body.get("servicenow_payload") if isinstance(req_body, dict) and "servicenow_payload" in req_body else req_body

    # Which ServiceNow table to post to
    servicenow_table = os.getenv("SERVICE_NOW_TABLE", "incident")

    try:
        url = _build_servicenow_url(servicenow_table)
    except ValueError as ex:
        logging.error("Configuration error: %s", ex)
        return func.HttpResponse(json.dumps({"error": str(ex)}), status_code=500, mimetype="application/json")

    headers = _get_auth_headers()
    basic_auth = _get_basic_auth()
    proxies = _build_proxies()

    # SSL verification
    verify = True
    if os.getenv("PROXY_VERIFY", "true").lower() in ("false", "0", "no"):
        verify = False

    try:
        logging.info("Forwarding request to ServiceNow: %s", url)
        # Use POST to create a new record
        if basic_auth and not headers.get("Authorization"):
            resp = requests.post(url, json=payload, headers=headers, auth=basic_auth, proxies=proxies, timeout=30, verify=verify)
        else:
            # If token-based auth is used, requests will use headers only
            resp = requests.post(url, json=payload, headers=headers, proxies=proxies, timeout=30, verify=verify)

        # Try to parse JSON response from ServiceNow
        try:
            sn_json = resp.json()
        except ValueError:
            sn_json = {"text": resp.text}

        # Return the full ServiceNow response JSON as-is so the calling Logic App can parse it.
        result = {
            "service_now_status_code": resp.status_code,
            "service_now_response": sn_json,
        }

        status_code = 200 if 200 <= resp.status_code < 300 else 502
        return func.HttpResponse(json.dumps(result), status_code=status_code, mimetype="application/json")

    except requests.RequestException as e:
        logging.exception("Error when calling ServiceNow API")
        return func.HttpResponse(json.dumps({"error": "Failed to call ServiceNow API", "details": str(e)}), status_code=502, mimetype="application/json")
