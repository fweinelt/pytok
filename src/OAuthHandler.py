import requests
import http.server
import socketserver
import urllib.parse as urlparse
import random
import hashlib
import threading
import webbrowser
import time

class OAuthManager:
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = OAuthHandler
        return cls._instance

class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    _PORT = 3456
    _CLIENT_KEY = ''
    _CLIENT_SECRET = ''
    _REDIRECT_URI = f'http://127.0.0.1:{_PORT}/callback/'
    _AUTHORIZATION_URL = 'https://www.tiktok.com/v2/auth/authorize/'
    _TOKEN_URL = 'https://open.tiktokapis.com/v2/oauth/token/'
    _SCOPES = 'user.info.basic'
    _OAUTH_SUCCESS = False
    _CURRENT_ACCESS_TOKEN = ''
    _CURRENT_REFRESH_TOKEN = ''

    _csrf_state = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(16))
    _code_verifier = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~') for x in range(64))

    class CustomTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    def do_GET(self):
        if self.path.startswith('/oauth'):
            self._handle_oauth()
        elif self.path.startswith('/callback'):
            self._handle_callback()
        else:
            super().do_GET()

    @classmethod
    def start_server(cls):
        if cls._CLIENT_KEY == '' or cls._CLIENT_SECRET == '':
            raise RuntimeError('Client key, secret or both missing')
        handler = cls
        with cls.CustomTCPServer(("", cls._PORT), handler) as httpd:
            print(f"Serving at port {cls._PORT}")
            webbrowser.open_new_tab(f'http://127.0.0.1:{cls._PORT}/oauth/')
            try:
                while not cls._OAUTH_SUCCESS:
                    httpd.handle_request()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()

    @staticmethod
    def _sha256_hash(input_string):
        sha256 = hashlib.sha256()
        sha256.update(input_string.encode())
        return sha256.hexdigest()

    def _handle_oauth(self):
        code_challenge = self._sha256_hash(self._code_verifier)
        params = {
            'client_key': self._CLIENT_KEY,
            'scope': self._SCOPES,
            'redirect_uri': self._REDIRECT_URI,
            'state': self._csrf_state,
            'response_type': 'code',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        self.send_response(302)
        self.send_header('Location', self._AUTHORIZATION_URL + '?' + urlparse.urlencode(params))
        self.end_headers()

    def _handle_callback(self):
        query = urlparse.urlparse(self.path).query
        params = urlparse.parse_qs(query)
        state = params.get('state', [None])[0]
        code = params.get('code', [None])[0]
        error = params.get('error', [None])[0]

        if error:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Error: {params.get('error_description', ['Unknown error'])[0]}".encode())
            return

        if state != self._csrf_state:
            self.send_response(400)
            self.end_headers()
            self.wfile.write("Error: Invalid state parameter".encode())
            return
        
        token_response_data = self._fetch_access_token(code)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        if 'error' in token_response_data:
            self.wfile.write(f"Error fetching access token: {token_response_data}".encode())
        else:
            self.wfile.write(f"Authorization workflow successful".encode())
            OAuthHandler._OAUTH_SUCCESS = True
            OAuthHandler._CURRENT_ACCESS_TOKEN = token_response_data['access_token']
            OAuthHandler._CURRENT_REFRESH_TOKEN = token_response_data['refresh_token']

    @classmethod
    def oath_workflow(cls, timeout = 30):
        server_thread = threading.Thread(target=cls.start_server)
        server_thread.daemon = True
        server_thread.start()
        
        start_time = time.time()
        try:
            while not cls.is_oauth_success():
                if time.time() - start_time > timeout:
                    print('OAuth workflow timeout of '+str(timeout)+' seconds reached')
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            return('Keyboard interrupt')
        finally:
            return('OAuth process completed.')

    @staticmethod
    def _fetch_access_token(code):
        data = {
            'client_key': OAuthHandler._CLIENT_KEY,
            'client_secret': OAuthHandler._CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': OAuthHandler._REDIRECT_URI,
            'code_verifier': OAuthHandler._code_verifier
        }
        response = requests.post(OAuthHandler._TOKEN_URL, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data)
        return response.json()

    @classmethod
    def refresh_access_token(cls):
        data = {
            'client_key': cls._CLIENT_KEY,
            'client_secret': cls._CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': cls._CURRENT_REFRESH_TOKEN
        }
        response = requests.post(cls._TOKEN_URL, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data)
        return response.json()

    @staticmethod
    def _revoke_access_token():
        data = {
            'client_key': OAuthHandler._CLIENT_KEY,
            'client_secret': OAuthHandler._CLIENT_SECRET,
            'token': OAuthHandler._CURRENT_ACCESS_TOKEN
        }
        response = requests.post('https://open.tiktokapis.com/v2/oauth/revoke/', headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }, data=data)
        return response.json()

    @classmethod
    def set_port(cls, port):
        cls._PORT = port
        cls._REDIRECT_URI = f'http://127.0.0.1:{cls._PORT}/callback/'

    @classmethod
    def get_port(cls):
        return cls._PORT

    @classmethod
    def set_scopes(cls, scopes):
        cls._SCOPES = scopes

    @classmethod
    def get_scopes(cls):
        return cls._SCOPES

    @classmethod
    def set_client_key(cls, client_key):
        cls._CLIENT_KEY = client_key

    @classmethod
    def get_client_key(cls):
        return cls._CLIENT_KEY

    @classmethod
    def set_client_secret(cls, client_secret):
        cls._CLIENT_SECRET = client_secret

    @classmethod
    def get_client_secret(cls):
        return cls._CLIENT_SECRET

    @classmethod
    def set_redirect_uri(cls, redirect_uri):
        cls._REDIRECT_URI = redirect_uri

    @classmethod
    def get_redirect_uri(cls):
        return cls._REDIRECT_URI

    @classmethod
    def get_current_access_token(cls):
        return cls._CURRENT_ACCESS_TOKEN

    @classmethod
    def get_authorization_url(cls):
        return cls._AUTHORIZATION_URL

    @classmethod
    def get_token_url(cls):
        return cls._TOKEN_URL

    @classmethod
    def is_oauth_success(cls):
        return cls._OAUTH_SUCCESS