package apibase

import (
	"encoding/json"
	"fmt"
)

func (x Shopware6StoreFrontClientBase) Request_delete(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_dict("delete", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}
	return response_dict, err
}

func (x Shopware6StoreFrontClientBase) Request_get(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_dict("get", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}

	return response_dict, nil
}

func (x Shopware6StoreFrontClientBase) Request_get_list(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_l_dict, err := x.request_list("get", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}

	return response_l_dict, nil
}

func (x Shopware6StoreFrontClientBase) Request_patch(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_dict("patch", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6StoreFrontClientBase) Request_post(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_dict("post", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6StoreFrontClientBase) Request_put(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_dict("put", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6StoreFrontClientBase) request_dict(
	http_method string,
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response, err := x.request(http_method, request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}
	// if hasattr(response, "json"):  # pragma: no cover
	//           response_json = response.json()  # type: ignore
	//           if isinstance(response_json, list):
	//               raise ShopwareAPIError(f"received a list instead of a dict - You need to use the method request_{http_method}_list")
	//           response_dict = dict(response_json)
	//       else:
	//           response_dict = dict()  # pragma: no cover
	//       return response_dict
	return response, nil
}

func (x Shopware6StoreFrontClientBase) request_list(
	http_method string,
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response, err := x.request(http_method, request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}

	// if hasattr(response, "json"):  # pragma: no cover
	//           response_json = response.json()  # type: ignore
	//           if isinstance(response_json, dict):
	//               raise ShopwareAPIError(f"received a dict instead of a list - You need to use the method request_{http_method}")
	//           response_l_dict = list(response_json)
	//       else:
	//           response_l_dict = list()  # pragma: no cover
	return response, nil
}

func (x Shopware6StoreFrontClientBase) request(
	http_method string,
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	// if isinstance(payload, Criteria):
	//           payload = payload.get_dict()
	// TODO: Das ist schon da, muss eingebunden werden, wenn soweit fertig.
	// storefront_api_url := x.build_storefront_api_url(request_url)
	//       response: requests.Response = requests.Response()
	// headers, err := x.get_headers(update_header_fields)
	// if err != nil {
	// return nil, err
	// }

	// TODO: Alles hier!
	// if http_method == "get":
	//          response = requests.request("GET", storefront_api_url, params=payload, headers=headers)
	//      elif http_method == "patch":
	//          response = requests.request("PATCH", storefront_api_url, data=json.dumps(payload), headers=headers)
	//      elif http_method == "post":
	//          response = requests.request("POST", storefront_api_url, data=json.dumps(payload), headers=headers)
	//      elif http_method == "put":
	//          response = requests.request("PUT", storefront_api_url, data=json.dumps(payload), headers=headers)
	//      elif http_method == "delete":
	//          response = requests.request("DELETE", storefront_api_url, headers=headers)
	//
	//      try:
	//          response.raise_for_status()
	//      except Exception as exc:
	//          if hasattr(exc, "response"):  # pragma: no cover
	//              detailed_error = f" : {exc.response.text}"  # type: ignore
	//          else:
	//              detailed_error = ""  # pragma: no cover
	//          raise ShopwareAPIError(f"{exc}{detailed_error}")
	//

	var response []any

	return response, nil
}


func (x Shopware6StoreFrontClientBase) get_headers(update_header_fields Headers) ([]byte, error) {
	var header Headers
	header.ContentType = "application/json"
	header.Accept = "application/json"
	header.SWAccessKey = x.Config.store_api_sw_access_key
	header = x.update_headers(update_header_fields, header)

	Header, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	return Header, nil
}

func (x Shopware6StoreFrontClientBase) update_headers(
	update_header_fields Headers,
	header Headers,
) Headers {

	header_copy := header

	if len(update_header_fields.SWAccessKey) > 0 {
		header_copy.SWAccessKey = update_header_fields.SWAccessKey
	}
	if len(update_header_fields.Accept) > 0 {
		header_copy.Accept = update_header_fields.Accept
	}
	if len(update_header_fields.ContentType) > 0 {
		header_copy.ContentType = update_header_fields.ContentType
	}

	return header_copy
}

func (x Shopware6StoreFrontClientBase) build_storefront_api_url(endpoint string) string {
	return fmt.Sprintf("%s/%s", x.Config.shopware_storefront_api_url, endpoint)
}


func (x Shopware6AdminApiClientBase) Request_get(
	request_url string,
	payload Payload,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.make_request("get", request_url, payload, update_header_fields)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) Request_get_paginated(
	request_url string,
	payload Payload,
	junk_size int,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_paginated(
		"get",
		request_url,
		payload,
		junk_size,
		update_header_fields,
	)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) Request_patch(
	request_url string,
	payload Payload,
	content_type string,
	additional_query_params []byte,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.make_request(
		"patch",
		request_url,
		payload,
		content_type,
		additional_query_params,
		update_header_fields,
	)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) Request_post(
	request_url string,
	payload Payload,
	content_type string,
	additional_query_params []byte,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.make_request(
		"post",
		request_url,
		payload,
		content_type,
		additional_query_params,
		update_header_fields,
	)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) Request_post_paginated(
	request_url string,
	payload Payload,
	junk_size int,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.request_paginated(
		"post",
		request_url,
		payload,
		junk_size,
		update_header_fields,
	)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) Request_put(
	request_url string,
	payload Payload,
	content_type string,
	additional_query_params []byte,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.make_request(
		"put",
		request_url,
		payload,
		content_type,
		additional_query_params,
		update_header_fields,
	)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) Request_delete(
	request_url string,
	payload Payload,
	additional_query_params []byte,
	update_header_fields Headers,
) ([]any, error) {
	response_dict, err := x.make_request(
		"delete",
		request_url,
		payload,
		additional_query_params,
		update_header_fields,
	)
	if err != nil {
		return nil, err
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) request_paginated(
	http_method string,
	request_url string,
	payload Payload,
	junk_size int,
	update_header_fields Headers,
) ([]any, error) {
	var response_dict []any
	payload_dict := x.get_payload_dict(payload)
	var ids_limit int
	var junksize int = junk_size
	if x.is_type_crieria(payload) {
		if payload.ids {
			ids_limit = len(payload.ids)
			junksize = ids_limit
			payload_dict.limit = ids_limit
		}
	}

	var total_limit any
	var records_left any
	// total_limit := Union[None, int] // TODO: Type
	// records_left := Union[None, int] // Todo: type

	if payload_dict.limit != 0 {
		total_limit = payload_dict.limit
	} else {
		total_limit = nil
	}

	if total_limit == nil {
		payload_dict.limit = junk_size
		records_left = nil
	} else {
		payload_dict.limit = min(total_limit, junk_size) // TODO: Funktion
		records_left = total_limit
	}

	var page int = 1
	for true {
		payload_dict.page = page

		partial_data, err := x.make_request(
			http_method,
			request_url,
			payload_dict,
			update_header_fields,
		)
		if err != nil {
			return nil, err
		}
		if partial_data.data {
			response_dict.data = response_dict.data + partial_data.data
			page = page + 1
			if total_limit != nil {
				records_left = records_left - len(partial_data.data)
				if records_left < 1 {
					response_dict.data = response_dict.data[:total_limit]
					break
				}
			}
		} else {
			break
		}
	}
	return response_dict, nil
}

func (x Shopware6AdminApiClientBase) make_request(
	http_method string,
	request_url string,
	payload Payload,
	content_type string,
	additional_query_params []byte,
	update_header_fields Headers,
) ([]any, error) {
	var retry int = 2
	for true {
	  try {
	    self._get_session()
                response = self._request(
                    http_method=http_method,
                    request_url=request_url,
                    payload=payload,
                    content_type=content_type,
                    additional_query_params=additional_query_params,
                    update_header_fields=update_header_fields,
                )
                retry = 0
       except requests_oauthlib.TokenUpdated as exc:
                self._token_saver(token=exc.token)
                response = self._request(
                    http_method=http_method,
                    request_url=request_url,
                    payload=payload,
                    content_type=content_type,
                    additional_query_params=additional_query_params,
                    update_header_fields=update_header_fields,
                )
                retry = 0
            except TokenExpiredError:
                if self._is_refreshable_token():  # pragma: no cover
                    # this actually should never happen - just in case.
                    logger.warning("something went wrong - the token should have been automatically refreshed. getting a new token")  # pragma: no cover
                    self._get_access_token_by_user_credentials()  # pragma: no cover
                else:
                    self._get_access_token_by_resource_owner()
                self._get_session()
                response = self._request(
                    http_method=http_method,
                    request_url=request_url,
                    payload=payload,
                    content_type=content_type,
                    additional_query_params=additional_query_params,
                    update_header_fields=update_header_fields,
                )
                retry = 0
            except ShopwareAPIError as exc:
                """
                retry   : how often to retry - sometimes we get error code:9, status:401, The resource owner or authorization server denied the request,
                detail: Access token could not be verified.
                But it works if You try again, it seems to be an error in shopware API or race condition
                """
                retry = retry - 1
                if not retry:
                    raise exc

            if not retry:
                break
    try:
            # noinspection PyUnboundLocalVariable
            response_dict = dict(response.json())
        except Exception:  # noqa
            response_dict = dict()
        return response_dict
    }
  }
}

func (x Shopware6AdminApiClientBase) request(http_method string, request_url string, payload Payload, content_type string, additional_query_params []byte, update_header_fields Headers) (any, error) {
  request_data: Union[str, PayLoad]
        payload_dict = dict()

        if _is_type_bytes(payload):
            request_data = payload
            if content_type.lower() == "json":
                raise ShopwareAPIError('Content type "json" does not match the payload data type "bytes"')
        else:
            payload_dict = _get_payload_dict(payload)
            request_data = json.dumps(payload_dict)

        if not additional_query_params:
            additional_query_params = dict()

        response: requests.Response = requests.Response()
        headers = self._get_headers(content_type=content_type, update_header_fields=update_header_fields)

        if http_method == "get":
            if additional_query_params:
                raise ShopwareAPIError("query parameters for GET requests need to be provided as payload")
            response = self.session.get(self._format_admin_api_url(request_url), params=payload_dict, headers=headers)
        elif http_method == "patch":
            response = self.session.patch(self._format_admin_api_url(request_url), data=request_data, headers=headers, params=additional_query_params)
        elif http_method == "post":
            response = self.session.post(self._format_admin_api_url(request_url), data=request_data, headers=headers, params=additional_query_params)
        elif http_method == "put":
            response = self.session.put(self._format_admin_api_url(request_url), data=request_data, headers=headers, params=additional_query_params)
        elif http_method == "delete":
            response = self.session.delete(self._format_admin_api_url(request_url), params=additional_query_params)

        try:
            response.raise_for_status()
        except Exception as exc:
            if hasattr(exc, "response"):
                detailed_error = f" : {exc.response.text}"  # type: ignore
            else:
                detailed_error = ""
            raise ShopwareAPIError(f"{exc}{detailed_error}")

        return response
}

func (x Shopware6AdminApiClientBase) get_token() (any, error) {
  if self.config.grant_type == "user_credentials":
            token = self._get_access_token_by_user_credentials()
        elif self.config.grant_type == "resource_owner":
            token = self._get_access_token_by_resource_owner()
        else:
            raise ShopwareAPIError(f'config.grant_type must bei either "user_credentials" or "resource_owner" not "{str(self.config.grant_type)}"')
        return token
}

func (x Shopware6AdminApiClientBase) get_access_token_by_ressource_owner() (any, error ) {
   if not self.config.shopware_admin_api_url:
            raise ShopwareAPIError("shopware_api_url needed")
        if not self.config.client_id:
            raise ShopwareAPIError("client_id needed")
        if not self.config.client_secret:
            raise ShopwareAPIError("client_secret needed")

        additional_parameters = {"grant_type": "user_credentials"}
        client = oauthlib.oauth2.BackendApplicationClient(client_id=self.config.client_id)
        oauth = requests_oauthlib.OAuth2Session(client=client)
        self.token = oauth.fetch_token(
            token_url=self._format_admin_api_url("oauth/token"),
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            kwargs=additional_parameters,
        )
        return self.token
}

func (x Shopware6AdminApiClientBase) get_access_token_by_user_credentials() (any, error) {
  if not self.config.shopware_admin_api_url:
            raise ShopwareAPIError("shopware_api_url needed")
        if not self.config.username:
            raise ShopwareAPIError("username needed")
        if not self.config.password:
            raise ShopwareAPIError("password needed")

        client_id = "administration"
        additional_parameters = {"grant_type": "password", "scopes": "write"}
        client = oauthlib.oauth2.LegacyApplicationClient(client_id=client_id)
        session_oauth = requests_oauthlib.OAuth2Session(client=client)
        self.token = session_oauth.fetch_token(
            token_url=self._format_admin_api_url("oauth/token"),
            client_id=client_id,
            username=self.config.username,
            password=self.config.password,
            kwargs=additional_parameters,
        )
        return self.token
}

func (x Shopware6AdminApiClientBase) get_session() {
   try:
            if not self.token:
                self._get_token()
            if self._is_refreshable_token():
                self.token["expires_in"] = int(self.token["expires_at"] - time.time())
                client_id = "administration"
                extra = {"client_id": client_id}
                self.session = requests_oauthlib.OAuth2Session(
                    client_id, token=self.token, auto_refresh_kwargs=extra, auto_refresh_url=self._format_admin_api_url("oauth/token")
                )
            else:
                client_id = self.config.client_id
                self.session = requests_oauthlib.OAuth2Session(client_id, token=self.token)
        except requests_oauthlib.TokenUpdated as exc:   # pragma: no cover
            self._token_saver(token=exc.token)          # pragma: no cover
}

func (x Shopware6AdminApiClientBase) token_saver(token any) {
  self.token = token
}

func (x Shopware6AdminApiClientBase) is_refreshable_token() boolean {
   return "refresh_token" in self.token
}


func (x Shopware6AdminApiClientBase) format_admin_api_url(request_url string) string {
  request_url = request_url.lstrip("/")
        return f"{self.config.shopware_admin_api_url}/{request_url}"
}

func (x Shopware6AdminApiClientBase) get_headers(content_type string, update_header_fields Headers) Headers {
  headers = {"Content-Type": f"application/{content_type.lower()}", "Accept": "application/json"}
        if update_header_fields is not None:
            headers.update(update_header_fields)
        return headers
}

func load_config(use_docker_test_container boolean) Config {
   if _is_github_actions() or use_docker_test_container:  # pragma: no cover
        config = _load_config_for_docker_test_container()
        config.store_api_sw_access_key = _get_docker_test_container_store_access_key()
        _create_docker_test_container_resource_owner_credentials()
    else:
        config = _load_config_for_rotek_production()  # pragma: no cover
    return config
}

  func load_config_for_docker_test_container() Config {
  try:
        from conf_shopware6_api_base_docker_testcontainer import conf_shopware6_api_base
    except ImportError:  # pragma: no cover
        # Imports for Doctest
        from .conf_shopware6_api_base_docker_testcontainer import conf_shopware6_api_base  # type: ignore  # pragma: no cover
    return conf_shopware6_api_base  # type: ignore
  }

  func get_docker_test_container_store_access_key() string {
   config = _load_config_for_docker_test_container()
    admin_api_client = Shopware6AdminAPIClientBase(config=config)
    admin_api_client._get_access_token_by_user_credentials()
    admin_api_client._get_session()
    response_dict = admin_api_client.request_get("sales-channel")
    access_key = str(response_dict["data"][0]["accessKey"])
    return access_key
  }

  func create_docker_test_container_resource_owner_credentials() {
  if not _is_resource_owner_credentials_present():
        _upsert_docker_test_container_resource_owner_credentials()
  }

func upsert_docker_test_container_resource_owner_credentials() {
   payload = {
        "id": "565c4ada878141d3b18d6977dbbd2a13",  # noqa
        "label": "dockware_integration_admin",  # noqa
        "accessKey": "SWIACWJOMUTXV1RMNGJUAKTUAA",  # noqa
        "secretAccessKey": "UkhvUG1qdmpuMjFudGJCdG1Xc0xMbEt2ck9CQ2xDTUtXMUZHRUQ",  # noqa
        "admin": True,
    }  # noqa
    config = _load_config_for_docker_test_container()
    admin_api_client = Shopware6AdminAPIClientBase(config=config)
    admin_api_client._get_access_token_by_user_credentials()
    admin_api_client._get_session()
    admin_api_client.request_post("integration", payload=payload)
  }

func Is_ressource_owner_credentials_present() boolean {
   config = _load_config_for_docker_test_container()
    admin_api_client = Shopware6AdminAPIClientBase(config=config)
    admin_api_client._get_access_token_by_user_credentials()
    admin_api_client._get_session()
    response_dict = admin_api_client.request_post("search/integration")
    if response_dict["total"]:
        resource_owner_credentials_present = True
    else:
        resource_owner_credentials_present = False
    return resource_owner_credentials_present
}

func load_config_for_rotek_production() Config {
 try:  # pragma: no cover
        from conf_shopware6_api_base_rotek import conf_shopware6_api_base  # pragma: no cover
    except ImportError:  # pragma: no cover
        # Imports for Doctest
        from .conf_shopware6_api_base_rotek import conf_shopware6_api_base  # type: ignore  # pragma: no cover
    return conf_shopware6_api_base  # type: ignore
}

func is_github_actions() boolean {
return os.getenv("GITHUB_ACTIONS", "false").lower() == "true"
}

func is_local_docker_container_active() {
try:
        requests.get("http://localhost/admin")
        is_active = True
    except requests.exceptions.ConnectionError:  # pragma: no cover 
        is_active = False  # pragma: no cover
    return is_active
}

func is_type_bytes(payload Payload) bool {
   return type(payload).__name__ == "bytes"
}

func is_type_criteria(payload Payload) bool {
   return type(payload).__name__ == "Criteria"
}

func get_payload_dict(payload Payload) []any {
if payload is None:
        payload = dict()
    elif _is_type_criteria(payload):
        payload = payload.get_dict()  # type: ignore
    return payload  # type: ignore
}

