from typing import Union

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/metadata")
async def metadata(request: Request):
    settings = OneLogin_Saml2_Settings(custom_base_path='./')
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = Response(content=metadata, media_type="text/xml")
    else:
        resp = Response(content=', '.join(errors), media_type="text/plain")
    return resp


@app.get("/login")
async def login(request: Request):
    req = parse_request(request)
    print('start=========')
    saml_auth = OneLogin_Saml2_Auth(req, custom_base_path='./')
    # Generate the SAML authentication request
    auth_url = saml_auth.login()
    # Redirect the user to the IDP login page
    return RedirectResponse(url=auth_url)


@app.post('/login/callback')
async def saml_login_callback(request: Request):
    req = await prepare_from_fastapi_request(request, True)
    auth = init_saml_auth(req)
    auth.process_response()  # Process IdP response
    errors = auth.get_errors()  # This method receives an array with the errors
    if len(errors) == 0:
        if not auth.is_authenticated():  # This check if the response was ok and the user data retrieved or not (user authenticated)
            return "user Not authenticated"
        else:
            attributes = auth.get_attributes()
            print(attributes)
            url = f"http://sulmo.link?email={attributes.get('email')[0]}"
            return RedirectResponse(url=url)
    else:
        print("Error when processing SAML Response: %s %s" % (', '.join(errors), auth.get_last_error_reason()))
        return "Error in callback"


def parse_request(request):
    request_dict = {'get_data': request.query_params,
                    'https': 'on',
                    'http_host': request.headers['host'], 'script_name': request.url.path,
                    'server_port': request.client.port,
                    'hostname': request.client.host
                    }

    return request_dict


def init_saml_auth(request: Request):
    saml_auth = OneLogin_Saml2_Auth(request, custom_base_path='./')
    print(saml_auth.__dict__)

    return saml_auth


async def prepare_from_fastapi_request(request, debug=False):
    form_data = await request.form()
    rv = {
        "http_host": 'localhost:8000',
        "server_port": request.url.port,
        "script_name": request.url.path,
        "post_data": {},
        "get_data": {}
        # Advanced request options
        # "https": "",
        # "request_uri": "",
        # "query_string": "",
        # "validate_signature_from_qs": False,
        # "lowercase_urlencoding": False
    }
    if (request.query_params):
        rv["get_data"] = request.query_params,
    if "SAMLResponse" in form_data:
        SAMLResponse = form_data["SAMLResponse"]
        rv["post_data"]["SAMLResponse"] = SAMLResponse
    if "RelayState" in form_data:
        RelayState = form_data["RelayState"]
        rv["post_data"]["RelayState"] = RelayState
    return rv
