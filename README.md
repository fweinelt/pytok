# PyTok - a Python implementation of the TikTok API

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.1.0-brightgreen.svg)

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [TODOs](#todos)
- [Changelog](#changelog)

## Introduction

A Python implementation of the TikTok API enables interaction with TikTok's services through programmatic access. It typically involves OAuth2 authentication to securely complete the login process and subsequently access the users data. You can retrieve user profiles, including basic information like usernames and IDs or automate more advanced tasks like posting and managing content, such as videos and comments. Rate limiting and API quotas should be respected to avoid service interruptions. API keys from TikTok's [developer portal](https://developers.tiktok.com/doc/overview/) are an essential prerequisit for integration, though a sandbox is sufficient for most test cases.

If you have suggestions, feedback or are looking to collaborate be sure to contact me at [fabian.weinelt@uni-bayreuth.de](mailto:fabian.weinelt@uni-bayreuth.de).

## Features

Currently implemented API features include

### LoginKit

The LoginKit class provides a comprehensive solution for interacting with TikTok's OAuth 2.0 authentication system. It is designed to facilitate the OAuth authentication workflow with TikTok, handle web server requests for OAuth and callbacks, and manage the resulting access tokens for use in making API requests. Features include

- **Login using a browser:** Using `oauth_server` one can initiate a login workflow, which prompts the user in a browser window to log in via username and password and grant user specified permissions (scopes).This is done by starting a local TCP server to handle the authentification as well as the callback. Upon success, one recieves the access token for the requested scopes that can be used in conjuction with other API constituents. 

- **Login using a QR-Code**: Alternatively one may use a QR-Code to login from the mobile app instead of a username and password. By executing `generate_qr_code` one recieves a QR url used to generate the corresponding QR-Code. By initiating `oath_qrcode` PyTok waits for the code to be scanned and, upon success, recieves the access token exactly like the browser login method.

- **Multiple instances:** With now use of class methods, PyTok allows for as many instances as you want. Programatically controlling multiple TikTok accounts or using multiple apps is therefore possible.

- **Access Token Management:** Methods like `refresh_access_token`, and `revoke_access_token` manage the lifecycle of access tokens, refreshing and revoking tokens as needed. The current access token can always be accessed by its property attribute `current_access_token`.

- **Initialization:** The `__init__` method initializes essential parameters including client credentials, server port, and OAuth settings. It also generates necessary values for CSRF state and code verifier used in the authentification process.

- **Properties:** Several properties (BASE_API_URL, CSRF_STATE_LENGTH, CODE_VERIFIER_LENGTH, etc.) have been defined to provide read-only access to important configuration values, ensuring encapsulation and controlled access to internal state.

## Installation

PyTok will soon be availabe via the Python Package Index (PyPI) und thus easily installable via ´pip´. Stay tuned...

## Usage

Here a few examples are brought up. Use them for testing and modify them to your needs.

# LoginKit

The simplest login procedure is done using ones browser. Firstly, an instance of `LoginKit` taking ones app client key and secret as mandatory arguments. By subsequently executing `oauth_server` one is prompted to sign into a TikTok account with their username and password. Upon success, the browser window displays "Authentification workflow completed" and can be closed. Lastly, the access token is printed to the terminal.

```python
from LoginKit import LoginKit
    
login_kit = LoginKit('YOUR_CLIENT_KEY', 'YOUR_CLIENT_SECRET')
login_kit.oath_server()

token = login_kit.current_access_token

print(token)
```

The QR-Code workflow is a little bit more complicated. Again, an app client key and secret must be given. The QR URL as well as a token and client ticket are generated with it. Those are needed for security, so that no other program or user can interfer with the ongoing workflow. Pythons built-in `qrcode` library is then used to generate the code out of the URL. Furthermore `os` and `webbrowser` are used to save the newly created QR-Code image locally and display it in the webbrowser. On a mobile app go to "Profile", tap the burger menu at the top right and tap "My QR-Code". Tap the icon at the top right again to open the scanner and scan the QR-Code. Upon success, the access token will again be printed to the terminal.

```python
from LoginKit import LoginKit
import qrcode
import os
import webbrowser
    
login_kit = LoginKit('YOUR_CLIENT_KEY', 'YOUR_CLIENT_SECRET')

qr_url, qr_token, qr_client_ticket = login_kit.generate_qr_code()
    
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(qr_url)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
    
img_path = "qr_code.png"
img.save(img_path)
webbrowser.open_new_tab(f"file://{os.path.realpath(img_path)}")
    
login_kit.oauth_qrcode(qr_token, qr_client_ticket)

print(login_kit.current_access_token)
```

## Configuration

Initializing an instance of `LoginKit` may take several optional arguments. These are

- `port` (int): Port used by the TCP server when calling `oauth_server`. It is configured to allow for reusage. Default value is 3456.
- `scopes` (list of strings): List of permissions (scopes) one needs access to. Default value is "user.info.basic".
- `redirect_uri` (string): Web redirect URI given in the app in the TikTok developers portal. Default value is "http://127.0.0.1:3456/callback/"
- `authorization_url` (string): URL for authorization. Default value is "https://www.tiktok.com/v2/auth/authorize/"
- `base_api_url` (string): Base URL for most of TikToks API calls. Defualt value is "https://open.tiktokapis.com/v2/" 
- `csrf_state_length` (int): Length of the anti-forgery token used in the server workflow. Default value is 16
- `code_verifier_length` (int): Length of the generated code verifier. Must be between 43 and 128. Default value is 64.
- `client_ticket_length` (int): Length of the generated client ticket used is the QR-Code workflow. URL-encoded version must be under 512 characters. Default value is 64.
- `request_header` (dict): Header for HTTP requests. Default value is "{'Content-Type': 'application/x-www-form-urlencoded'}"

## TODOs

A list of ideas and features you can expect in the future.
- Implement ContentPostingAPI (WIP)
- Implement proper error handling
- Allow for updating the scopes during runtime
- Make a PyPI release
- Expand on the documentation

## Changelog

### 0.1.0

- Introduced the proper README.md you are reading right now.
- Specified data types for input arguments in LoginKit's __init__ method.
- Updated LoginKit's attribute names.
- LoginKit's `__SCOPES` attribute is now a set, was string before.

### pre 0.1.0

Experimented with different implementations, finally settling on a instance-based approach. Implemented the QR-Code workflow along the way.