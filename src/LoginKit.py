import requests
import http.server
import socketserver
import urllib.parse as urlparse
import random
import hashlib
import webbrowser
import time

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
            client_key,
            client_secret,
            port=3456,
            scopes='user.info.basic',
            redirect_uri='http://127.0.0.1:3456/callback/',
            authorization_url = 'https://www.tiktok.com/v2/auth/authorize/',
            base_api_url='https://open.tiktokapis.com/v2/',
            csrf_state_length = 16,
            code_verifier_length = 64,
            client_ticket_length = 64
        ):
        self._AUTHORIZATION_URL = authorization_url
        self._BASE_API_URL = base_api_url
        self._CSRF_STATE_LENGTH = csrf_state_length
        self._CODE_VERIFIER_LENGTH = code_verifier_length
        self._CLIENT_TICKET_LENGTH = client_ticket_length
        self._client_key = client_key
        self._client_secret = client_secret
        self._port = port
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._oauth_success = False
        self._csrf_state = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(self._CSRF_STATE_LENGTH))
        self._code_verifier = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(self._CODE_VERIFIER_LENGTH))
        self._current_access_token = None
        self._current_refresh_token = None

    # Property definitions

    @property
    def BASE_API_URL(self):
        return self._BASE_API_URL

    @property
    def CSRF_STATE_LENGTH(self):
        return self._CSRF_STATE_LENGTH
    
    @property
    def CODE_VERIFIER_LENGTH(self):
        return self._CODE_VERIFIER_LENGTH
    
    @property
    def CLIENT_TICKET_LENGTH(self):
        return self._CLIENT_TICKET_LENGTH
    
    @property
    def oauth_success(self):
        return self._oauth_success
    
    @property
    def current_access_token(self):
        return self._current_access_token
    
    @property
    def current_refresh_token(self):
        return self._current_refresh_token
    
    @property
    def client_key(self):
        return self._client_key
    
    @property
    def client_secret(self):
        return self._client_secret

    # Server OAuth handling

    def _handle_oauth(self, handler):
        code_challenge = self._sha256_hash(self._code_verifier)
        params = {
            'client_key': self._client_key,
            'scope': self._scopes,
            'redirect_uri': self._redirect_uri,
            'state': self._csrf_state,
            'response_type': 'code',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        handler.send_response(302)
        handler.send_header('Location', self._AUTHORIZATION_URL + '?' + urlparse.urlencode(params))
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

        if state != self._csrf_state:
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
            self._oauth_success = True
            self._current_access_token = token_response_data.get('access_token')
            self._current_refresh_token = token_response_data.get('refresh_token')

    def oath_server(self, timeout = 30, open_in_browser='new_tab'):
        handler = lambda *args, **kwargs: self.Handler(*args, login_kit=self, **kwargs)
        with self.TCPServer(("", self._port), handler) as httpd:
            print(f"Serving at port {self._port}")
            if open_in_browser == 'new_tab':
                webbrowser.open_new_tab(f'http://127.0.0.1:{self._port}/oauth/')
            elif open_in_browser == 'new_window':
                webbrowser.open_new(f'http://127.0.0.1:{self._port}/oauth/')
            
            start_time = time.time()
            try:
                while not self._oauth_success:
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
            'client_key': self._client_key,
            'scope': self._scopes,
            'state': self._csrf_state
        }
        response = requests.post(self._BASE_API_URL+'oauth/get_qrcode/', headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data)
        response_data = response.json()

        if 'error' in response_data:
            return
        else:
            client_ticket = urlparse.quote(''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(self._CLIENT_TICKET_LENGTH)))
            scan_qrcode_url = response_data.get('scan_qrcode_url')
            return (scan_qrcode_url.replace('tobefilled', client_ticket), response_data.get('token'), client_ticket)

    def _check_qr_code_status(self, token):
        data = {
            'client_key': self._client_key,
            'client_secret': self._client_secret,
            'token': token
        }
        response = requests.post(self._BASE_API_URL+'oauth/check_qrcode/', headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data)
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
                    self._oauth_success = True
                    self._current_access_token = token_response_data['access_token']
                    self._current_refresh_token = token_response_data['refresh_token']
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
            'client_key': self._client_key,
            'client_secret': self._client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self._redirect_uri,
            'code_verifier': self._code_verifier
        }
        response = requests.post(self._BASE_API_URL+'oauth/token/', headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data)
        return response.json()

    def refresh_access_token(self):
        data = {
            'client_key': self._client_key,
            'client_secret': self._client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': self._current_refresh_token
        }
        response = requests.post(self._BASE_API_URL+'oauth/token/', headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data)
        return response.json()

    def revoke_access_token(self):
        data = {
            'client_key': self._client_key,
            'client_secret': self._client_secret,
            'token': self._current_access_token
        }
        response = requests.post(self._BASE_API_URL+'/oauth/revoke/', headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }, data=data)
        return response.json()

    # Misc

    @staticmethod
    def _sha256_hash(input_string):
        sha256 = hashlib.sha256()
        sha256.update(input_string.encode())
        return sha256.hexdigest()
    
    def set_scopes(self, scopes):
        sc = scopes.replace(" ", "")
        scopelist = sc.split(',')
        for s in scopelist:
            if s not in ['user.info.basic', 'video.publish', 'video.upload', 'artist.certification.read', 'artist.certification.update', 'user.info.profile', 'user.info.stats', 'video.list']:
                raise RuntimeWarning('Requested scope '+str(s)+' unknown, continuing...')
        self._scopes = sc
