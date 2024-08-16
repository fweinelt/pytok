import requests
import http.server
import socketserver
import urllib.parse as urlparse
import random
import hashlib
import webbrowser
import time
from typing import Dict, List, Optional

class LoginKit:
    class TCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            self.login_kit = kwargs.pop('login_kit')
            super().__init__(*args, **kwargs)

        def do_GET(self):
            if self.path.startswith('/oauth'):
                self.login_kit._handle_oauth(self)
            elif self.path.startswith('/callback'):
                self.login_kit._handle_callback(self)
            else:
                super().do_GET()
    
    def __init__(self,
            client_key: str,
            client_secret: str,
            port: Optional[int] = 3456,
            scopes: Optional[List[str]] = ['user.info.basic'],
            redirect_uri: Optional[str] = 'http://127.0.0.1:3456/callback/',
            authorization_url: Optional[str] = 'https://www.tiktok.com/v2/auth/authorize/',
            base_api_url: Optional[str] = 'https://open.tiktokapis.com/v2/',
            csrf_state_length: Optional[int] = 16,
            code_verifier_length: Optional[int] = 64,
            client_ticket_length: Optional[int] = 64,
            request_header: Optional[Dict] = {'Content-Type': 'application/x-www-form-urlencoded'}
        ):
        self.__AUTHORIZATION_URL = authorization_url
        self.__BASE_API_URL = base_api_url
        self.__CSRF_STATE_LENGTH = csrf_state_length
        self.__CODE_VERIFIER_LENGTH = code_verifier_length
        self.__CLIENT_TICKET_LENGTH = client_ticket_length
        self.__CLIENT_KEY = client_key
        self.__CLIENT_SECRET = client_secret
        self.__PORT = port
        self.__REDIRECT_URI = redirect_uri
        scopes.append('user.info.basic')
        self.__SCOPES = set(scopes)
        self.__OAUTH_SUCCESS = False
        self.__CSRF_STATE = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(self.__CSRF_STATE_LENGTH))
        self.__CODE_VERIFIER = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(self.__CODE_VERIFIER_LENGTH))
        self.__CURRENT_ACCESS_TOKEN = None
        self.__CURRENT_REFRESH_TOKEN = None
        self.__REQUEST_HEADER = request_header

    # Property definitions

    @property
    def BASE_API_URL(self):
        return self.__BASE_API_URL

    @property
    def CSRF_STATE_LENGTH(self):
        return self.__CSRF_STATE_LENGTH
    
    @property
    def CODE_VERIFIER_LENGTH(self):
        return self.__CODE_VERIFIER_LENGTH
    
    @property
    def CLIENT_TICKET_LENGTH(self):
        return self.__CLIENT_TICKET_LENGTH
    
    @property
    def scopes(self):
        return self.__SCOPES

    @property
    def oauth_success(self):
        return self.__OAUTH_SUCCESS
    
    @property
    def current_access_token(self):
        return self.__CURRENT_ACCESS_TOKEN
    
    @property
    def current_refresh_token(self):
        return self.__CURRENT_REFRESH_TOKEN
    
    @property
    def client_key(self):
        return self.__CLIENT_KEY
    
    @property
    def client_secret(self):
        return self.__CLIENT_SECRET

    # Server OAuth handling

    def _handle_oauth(self, handler):
        code_challenge = self._sha256_hash(self.__CODE_VERIFIER)
        params = {
            'client_key': self.__CLIENT_KEY,
            'scope': ",".join(self.__SCOPES),
            'redirect_uri': self.__REDIRECT_URI,
            'state': self.__CSRF_STATE,
            'response_type': 'code',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        handler.send_response(302)
        handler.send_header('Location', self.__AUTHORIZATION_URL + '?' + urlparse.urlencode(params))
        handler.end_headers()

    def _handle_callback(self, handler):
        query = urlparse.urlparse(handler.path).query
        params = urlparse.parse_qs(query)
        state = params.get('state', [None])[0]
        code = params.get('code', [None])[0]
        error = params.get('error', [None])[0]

        if error:
            handler.send_response(400)
            handler.end_headers()
            handler.wfile.write(f"Error: {params.get('error_description', ['Unknown error'])[0]}".encode())
            return

        if state != self.__CSRF_STATE:
            handler.send_response(400)
            handler.end_headers()
            handler.wfile.write("Error: Invalid state parameter".encode())
            return
        
        token_response_data = self._fetch_access_token(code)
        
        handler.send_response(200)
        handler.send_header('Content-type', 'text/html')
        handler.end_headers()

        if 'error' in token_response_data:
            handler.wfile.write(f"Error fetching access token: {token_response_data}".encode())
        else:
            handler.wfile.write(f"Authorization workflow successful".encode())
            self.__OAUTH_SUCCESS = True
            self.__CURRENT_ACCESS_TOKEN = token_response_data.get('access_token')
            self.__CURRENT_REFRESH_TOKEN = token_response_data.get('refresh_token')

    def oath_server(self, timeout = 30, open_in_browser='new_tab'):
        handler = lambda *args, **kwargs: self.Handler(*args, login_kit=self, **kwargs)
        with self.TCPServer(("", self.__PORT), handler) as httpd:
            print(f"Serving at port {self.__PORT}")
            if open_in_browser == 'new_tab':
                webbrowser.open_new_tab(f'http://127.0.0.1:{self.__PORT}/oauth/')
            elif open_in_browser == 'new_window':
                webbrowser.open_new(f'http://127.0.0.1:{self.__PORT}/oauth/')
            
            start_time = time.time()
            try:
                while not self.__OAUTH_SUCCESS:
                    httpd.handle_request()
                    if time.time() - start_time > timeout:
                        print('OAuth workflow timeout of '+str(timeout)+' seconds reached')
                        break
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()

    # QR code workflow
    
    def generate_qr_code(self):
        data = {
            'client_key': self.__CLIENT_KEY,
            'scope': ",".join(self.__SCOPES),
            'state': self.__CSRF_STATE
        }
        response = requests.post(self.__BASE_API_URL+'oauth/get_qrcode/', headers=self.__REQUEST_HEADER, data=data)
        response_data = response.json()
        if 'error' in response_data:
            return
        else:
            client_ticket = urlparse.quote(''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(self.__CLIENT_TICKET_LENGTH)))
            scan_qrcode_url = response_data.get('scan_qrcode_url')
            return (scan_qrcode_url.replace('tobefilled', client_ticket), response_data.get('token'), client_ticket)

    def _check_qr_code_status(self, token):
        data = {
            'client_key': self.__CLIENT_KEY,
            'client_secret': self.__CLIENT_SECRET,
            'token': token
        }
        response = requests.post(self.__BASE_API_URL+'oauth/check_qrcode/', headers=self.__REQUEST_HEADER, data=data)
        return response.json()        

    def oauth_qrcode(self, token, client_ticket, timeout=30, check_status_delay=1):      
        start_time = time.time()

        while time.time() - start_time < timeout:
            status_response = self._check_qr_code_status(token)
            status = status_response.get('status')
            client_ticket_response = status_response.get('client_ticket')

            if client_ticket_response == client_ticket and status == 'confirmed':
                code = status_response.get('code')
                token_response_data = self._fetch_access_token(code)
        
                if 'error' in token_response_data:
                    return
                else:
                    self.__OAUTH_SUCCESS = True
                    self.__CURRENT_ACCESS_TOKEN = token_response_data['access_token']
                    self.__CURRENT_REFRESH_TOKEN = token_response_data['refresh_token']
                return

            elif status == 'expired':
                print('QR code expired.')
                return

            time.sleep(check_status_delay)
        print('Timeout reached without QR code confirmation.')
        return

    # Access token management

    def _fetch_access_token(self, code):
        data = {
            'client_key': self.__CLIENT_KEY,
            'client_secret': self.__CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.__REDIRECT_URI,
            'code_verifier': self.__CODE_VERIFIER
        }
        response = requests.post(self.__BASE_API_URL+'oauth/token/', headers=self.__REQUEST_HEADER, data=data)
        return response.json()

    def refresh_access_token(self):
        data = {
            'client_key': self.__CLIENT_KEY,
            'client_secret': self.__CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': self.__CURRENT_REFRESH_TOKEN
        }
        response = requests.post(self.__BASE_API_URL+'oauth/token/', headers=self.__REQUEST_HEADER, data=data)
        return response.json()

    def revoke_access_token(self):
        data = {
            'client_key': self.__CLIENT_KEY,
            'client_secret': self.__CLIENT_SECRET,
            'token': self.__CURRENT_ACCESS_TOKEN
        }
        response = requests.post(self.__BASE_API_URL+'/oauth/revoke/', headers=self.__REQUEST_HEADER, data=data)
        return response.json()

    # Misc

    @staticmethod
    def _sha256_hash(input_string):
        sha256 = hashlib.sha256()
        sha256.update(input_string.encode())
        return sha256.hexdigest()
    
    def set__SCOPES(self, scopes):
        sc = scopes.replace(" ", "")
        scopelist = sc.split(',')
        for s in scopelist:
            if s not in ['user.info.basic', 'video.publish', 'video.upload', 'artist.certification.read', 'artist.certification.update', 'user.info.profile', 'user.info.stats', 'video.list']:
                raise RuntimeWarning('Requested scope '+str(s)+' unknown, continuing...')
        self.__SCOPES = sc
