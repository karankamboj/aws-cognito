from fastapi import FastAPI, HTTPException, Depends, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import boto3
import jwt
import requests
from typing import Optional
import os
from datetime import datetime, timedelta
import hashlib
import hmac
import base64
from dotenv import load_dotenv
import secrets

app = FastAPI(title="FastAPI Cognito Auth", version="1.0.0")

load_dotenv(dotenv_path='config.env')

# Environment variables
COGNITO_REGION = os.environ.get('COGNITO_REGION')
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.environ.get('COGNITO_CLIENT_SECRET')
COGNITO_DOMAIN=os.getenv("COGNITO_DOMAIN")

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

REDIRECT_URI = os.getenv("REDIRECT_URI")

# Security scheme
security = HTTPBearer()

# Initialize Cognito client
cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

class GoogleLoginInitResponse(BaseModel):
    """Response for initiating Google login"""
    login_url: str
    state: str
    expires_at: datetime
    message: str = "Redirect user to login_url to authenticate with Google"

class ChangeGroupRequest(BaseModel):
    username: str
    target_group: str = "Admin"
    remove_from_all_other_groups: bool = True


class ForgotPasswordInit(BaseModel):
    username: str  # can be username or email alias, per your pool settings

class ForgotPasswordConfirm(BaseModel):
    username: str
    confirmation_code: str
    new_password: str
class ChangePasswordBody(BaseModel):
    old_password: str
    new_password: str

# Pydantic models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
class UserLogin(BaseModel):
    username: str
    password: str

class TokenValidationResponse(BaseModel):
    valid: bool
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    expires_at: Optional[int] = None
    token_type: Optional[str] = None
    message: str

class TokenResponse(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class UserProfile(BaseModel):
    username: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email_verified: bool = False

class EmailVerificationRequest(BaseModel):
    verification_code: str

class EmailVerificationCodeRequest(BaseModel):
    attribute_name: str = "email"

class ResendConfirmationRequest(BaseModel):
    identifier: str  # Can be email or username

# Helper functions
def get_secret_hash(username: str) -> str:
    """Generate secret hash for Cognito client secret"""
    if not COGNITO_CLIENT_SECRET:
        return None
    
    message = username + COGNITO_CLIENT_ID
    dig = hmac.new(
        COGNITO_CLIENT_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def get_cognito_public_keys():
    """Get Cognito public keys for token verification"""
    url = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    response = requests.get(url)
    return response.json()

def verify_token_online(token: str) -> dict:
    # print("verifying token online", token)
    try:

        # This call FAILS if the token was globally signed out or otherwise invalid.
        cognito_client.get_user(AccessToken=token)
        
        return True
    except cognito_client.exceptions.NotAuthorizedException:
        return False

def verify_token_offline(token: str) -> dict:
    """Verify JWT token from Cognito"""
    try:
        # Get public keys
        jwks = get_cognito_public_keys()
        
        # Decode token header to get kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']
        
        # Find the correct key
        key = None
        for jwk in jwks['keys']:
            if jwk['kid'] == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
                break
        
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: Unable to find appropriate key"
            )

        # Verify token
        payload = jwt.decode(
            token,
            key,
            algorithms=['RS256'],
            issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        )
        print("token payload:", payload)
        return payload
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
    
def which_token(token: str) -> dict:
    """Verify JWT token from Cognito"""
    try:
        # Verify token
        payload = jwt.decode(token, options={"verify_signature": False})
        print("token payload:", payload)
        username = payload.get('username', '')
        
        # Determine if federated based on username pattern
        federated_providers = {
            'Google_': 'Google',
            'Facebook_': 'Facebook', 
            'LoginWithAmazon_': 'Amazon',
            'SignInWithApple_': 'Apple',
            'SAML_': 'SAML',
            'OIDC_': 'OpenID Connect'
        }
        identity_provider = 'Cognito'
        
        for prefix, provider in federated_providers.items():
            if username.lower().startswith(prefix.lower()):
                identity_provider = provider
                break
        return {
            "token_type": identity_provider
            }
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current user from token"""
    token = credentials.credentials
    print("token:", token)
    return verify_token_offline(token)

def validate_token_middleware(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current user from token"""
    token = credentials.credentials
    try:
        claims = verify_token_online(token)
    except Exception as e:
        # if your verifier raises on invalid/expired/revoked
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if not claims:
        # if your verifier returns False/None on invalid/expired/revoked
        raise HTTPException(status_code=401, detail="Invalid or revoked token")

    return claims 

@app.get("/token-type")
def check_token_type(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current user from token"""
    token = credentials.credentials
    try:
        claims = which_token(token)
    except Exception as e:
        # if your verifier raises on invalid/expired/revoked
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if not claims:
        # if your verifier returns False/None on invalid/expired/revoked
        raise HTTPException(status_code=401, detail="Invalid or revoked token")

    return claims 

@app.get("/validate-token", dependencies=[Depends(validate_token_middleware)])
async def with_precheck():
    return {"message": "Success! Token is valid"}

@app.post("/revoke-refresh")
def revoke_refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Revoke a refresh token — invalidates all access tokens issued from it.
    """
    refresh_token = credentials.credentials
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Token": refresh_token
        }
        # if the app client has a secret, include it
        if COGNITO_CLIENT_SECRET:
            params["ClientSecret"] = COGNITO_CLIENT_SECRET

        resp = cognito_client.revoke_token(**params)
        # On success, resp is {} (empty dict) per docs
        return resp
    except cognito_client.exceptions.InvalidParameterException as e:
        raise HTTPException(status_code=400, detail=f"Invalid parameter: {e}")
    except cognito_client.exceptions.UnsupportedOperationException as e:
        raise HTTPException(status_code=400, detail=f"Unsupported operation: {e}")
    except cognito_client.exceptions.InternalErrorException as e:
        raise HTTPException(status_code=500, detail=f"Internal error during revoke: {e}")
    except cognito_client.exceptions.TooManyRequestsException as e:
        raise HTTPException(status_code=429, detail="Too many requests to revoke")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to revoke token: {e}")
    
@app.post("/logout", response_model=dict, dependencies=[Depends(validate_token_middleware)])
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout from all sessions"""
    try:
        access_token = credentials.credentials
        
        # Global sign out - revokes all refresh tokens for this user
        cognito_client.global_sign_out(AccessToken=access_token)
        
        return {"message": "User logged out from all devices successfully"}    
    
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")
    
# Authentication endpoints
@app.post("/register", response_model=dict)
async def register_user(user_data: UserRegister):
    """Register a new user with Cognito"""
    try:
        # Prepare user attributes
        user_attributes = [
            {'Name': 'email', 'Value': user_data.email},
        ]
        
        if user_data.first_name:
            user_attributes.append({'Name': 'given_name', 'Value': user_data.first_name})
        
        if user_data.last_name:
            user_attributes.append({'Name': 'family_name', 'Value': user_data.last_name})
        
        # Prepare signup parameters
        signup_params = {
            'ClientId': COGNITO_CLIENT_ID,
            'Username': user_data.username,
            'Password': user_data.password,
            'UserAttributes': user_attributes
        }
        
        # Add secret hash if client secret is configured
        secret_hash = get_secret_hash(user_data.username)
        if secret_hash:
            signup_params['SecretHash'] = secret_hash
        
        # Register user
        response = cognito_client.sign_up(**signup_params)

        cognito_client.admin_add_user_to_group(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=user_data.username,
            GroupName='Guests'
        )
        
        return {
            "message": "User registered successfully",
            "user_sub": response['UserSub'],
            "confirmation_required": not response.get('UserConfirmed', False)
        }
    
    except cognito_client.exceptions.UsernameExistsException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    except cognito_client.exceptions.InvalidPasswordException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid password: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/login", response_model=TokenResponse)
async def login_user(user_credentials: UserLogin):
    """Login user and return tokens"""
    try:
        # Prepare authentication parameters
        auth_params = {
            'USERNAME': user_credentials.username,
            'PASSWORD': user_credentials.password
        }
        
        # Add secret hash if client secret is configured
        secret_hash = get_secret_hash(user_credentials.username)
        if secret_hash:
            auth_params['SECRET_HASH'] = secret_hash
        
        # Initiate authentication
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters=auth_params
        )
        
        # Check if authentication is successful
        if 'AuthenticationResult' in response:
            auth_result = response['AuthenticationResult']
            # validationTokenResponse = verify_token(auth_result['AccessToken'])  # Verify token before returning
            # print("validation response", validationTokenResponse)
            return TokenResponse(
                access_token=auth_result['AccessToken'],
                id_token=auth_result['IdToken'],
                refresh_token=auth_result['RefreshToken'],
                expires_in=auth_result['ExpiresIn']
            )
        else:
            # Handle challenges (MFA, password reset, etc.)
            challenge_name = response.get('ChallengeName')
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Authentication challenge required: {challenge_name}"
            )
    
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    except cognito_client.exceptions.UserNotConfirmedException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account not confirmed. Please check your email for confirmation instructions."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@app.post("/refresh-token", response_model=TokenResponse)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Refresh access token using refresh token"""
    refresh_token = credentials.credentials
    try:
        response = cognito_client.get_tokens_from_refresh_token(
            ClientId=COGNITO_CLIENT_ID,
            ClientSecret=COGNITO_CLIENT_SECRET,
            RefreshToken= refresh_token
        )
        
        auth_result = response['AuthenticationResult']
        
        return TokenResponse(
            access_token=auth_result['AccessToken'],
            id_token=auth_result['IdToken'],
            refresh_token=refresh_token,  # Refresh token doesn't change
            expires_in=auth_result['ExpiresIn']
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {str(e)}"
        )

@app.post("/confirm-signup")
async def confirm_signup(username: str, confirmation_code: str):
    """Confirm user signup with verification code"""
    try:
        # Prepare confirmation parameters
        confirm_params = {
            'ClientId': COGNITO_CLIENT_ID,
            'Username': username,
            'ConfirmationCode': confirmation_code
        }
        
        # Add secret hash if client secret is configured
        secret_hash = get_secret_hash(username)
        if secret_hash:
            confirm_params['SecretHash'] = secret_hash
        
        cognito_client.confirm_sign_up(**confirm_params)
        
        return {"message": "User confirmed successfully"}
    
    except cognito_client.exceptions.CodeMismatchException:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid confirmation code"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Confirmation failed: {str(e)}"
        )

@app.post("/auth/resend-confirmation", response_model=dict)
async def resend_confirmation_code(request: ResendConfirmationRequest):
    """Resend confirmation signup code (supports email or username)"""
    try:
        resend_params = {
            'ClientId': COGNITO_CLIENT_ID,
            'Username': request.identifier
        }
        
        secret_hash = get_secret_hash(request.identifier)
        if secret_hash:
            resend_params['SecretHash'] = secret_hash
        
        response = cognito_client.resend_confirmation_code(**resend_params)
        
        delivery_details = response.get('CodeDeliveryDetails', {})
        destination = delivery_details.get('Destination', 'your registered email')
        delivery_medium = delivery_details.get('DeliveryMedium', 'EMAIL')
        
        return {
            "message": f"Confirmation code resent successfully to {destination} via {delivery_medium}"
        }
    
    
    except cognito_client.exceptions.UserNotFoundException:
        return {"message": "If the user exists, confirmation code has been resent"}
    except cognito_client.exceptions.LimitExceededException:
        raise HTTPException(status_code=429, detail="Too many requests. Please wait before requesting another code")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resend confirmation code: {str(e)}")

@app.get("/profile", response_model=UserProfile)
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return UserProfile(
        username=current_user.get('cognito:username'),
        email=current_user.get('email'),
        first_name=current_user.get('given_name'),
        last_name=current_user.get('family_name'),
        email_verified=current_user.get('email_verified', False)
    )

@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    """Example protected route"""
    return {
        "message": "This is a protected route",
        "user": current_user.get('cognito:username')
    }

@app.post("/forgot-password")
def forgot_password(body: ForgotPasswordInit):
    """
    Initiate password reset: sends a verification code to the user's email/SMS.
    """
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": body.username,
        }
        sh = get_secret_hash(body.username)
        if sh:
            params["SecretHash"] = sh

        resp = cognito_client.forgot_password(**params)
        details = resp.get("CodeDeliveryDetails", {})
        return {
            "message": "Password reset code sent",
            "delivery_medium": details.get("DeliveryMedium"),
            "destination": details.get("Destination"),
            "attribute_name": details.get("AttributeName"),
        }
    except cognito_client.exceptions.UserNotFoundException:
        # Avoid user enumeration: respond generically
        return {"message": "If the user exists, a reset code has been sent"}
    except cognito_client.exceptions.LimitExceededException:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    except cognito_client.exceptions.CodeDeliveryFailureException:
        raise HTTPException(status_code=500, detail="Failed to deliver the reset code.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate reset: {e}")

@app.post("/forgot-password/confirm")
def confirm_forgot_password(body: ForgotPasswordConfirm):
    """
    Confirm password reset by providing the code and the new password.
    """
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": body.username,
            "ConfirmationCode": body.confirmation_code,
            "Password": body.new_password,
        }
        sh = get_secret_hash(body.username)
        if sh:
            params["SecretHash"] = sh

        cognito_client.confirm_forgot_password(**params)
        return {"message": "Password has been reset successfully"}
    except cognito_client.exceptions.CodeMismatchException:
        raise HTTPException(status_code=400, detail="Invalid confirmation code.")
    except cognito_client.exceptions.ExpiredCodeException:
        raise HTTPException(status_code=400, detail="Confirmation code expired.")
    except cognito_client.exceptions.InvalidPasswordException as e:
        raise HTTPException(status_code=400, detail=f"Password does not meet policy: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to confirm reset: {e}")
    
@app.post("/change-password", dependencies=[Depends(validate_token_middleware)])
def change_password(
    body: ChangePasswordBody,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Change current user's password (requires valid AccessToken in Authorization header).
    """
    access_token = credentials.credentials
    try:
        cognito_client.change_password(
            PreviousPassword=body.old_password,
            ProposedPassword=body.new_password,
            AccessToken=access_token,
        )
        return {"message": "Password changed successfully"}
    except cognito_client.exceptions.NotAuthorizedException:
        # Wrong old password or invalid/expired token
        raise HTTPException(status_code=401, detail="Not authorized or invalid credentials")
    except cognito_client.exceptions.InvalidPasswordException as e:
        raise HTTPException(status_code=400, detail=f"Password policy violation: {e}")
    except cognito_client.exceptions.LimitExceededException:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    except cognito_client.exceptions.PasswordResetRequiredException:
        raise HTTPException(status_code=400, detail="Password reset required before changing password")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to change password: {e}")


# @app.get("/auth/google/direct-login")
# async def google_direct_login():
#     """Direct Google OAuth login (bypassing Cognito hosted UI)"""
    
#     import secrets
#     state = secrets.token_urlsafe(32)
    
#     # Direct Google OAuth URL
#     google_oauth_url = (
#         f"https://accounts.google.com/o/oauth2/v2/auth?"
#         f"response_type=code&"
#         f"client_id={GOOGLE_CLIENT_ID}&"
#         f"redirect_uri={REDIRECT_URI}&"
#         f"scope=openid+email+profile&"
#         f"state={state}"
#     )
    
#     return {
#         "google_oauth_url": google_oauth_url,
#         "state": state,
#         "message": "Use this for direct Google OAuth (requires additional handling)"
#     }

# @app.post("/auth/google/direct-callback")
# async def google_direct_callback(
#     code: str = Form(...),
#     state: str = Form(...)
# ):
#     """Handle direct Google OAuth callback (requires additional Cognito integration)"""
    
#     try:
#         # Exchange code for Google tokens
#         token_data = {
#             "code": code,
#             "client_id": GOOGLE_CLIENT_ID,
#             "client_secret": GOOGLE_CLIENT_SECRET,
#             "redirect_uri": REDIRECT_URI,
#             "grant_type": "authorization_code"
#         }
        
#         response = requests.post("https://oauth2.googleapis.com/token", data=token_data)
#         google_tokens = response.json()
        
#         if 'access_token' not in google_tokens:
#             raise HTTPException(status_code=400, detail="Failed to get Google tokens")
        
#         # Get user info from Google
#         user_info_response = requests.get(
#             "https://www.googleapis.com/oauth2/v2/userinfo",
#             headers={"Authorization": f"Bearer {google_tokens['access_token']}"}
#         )
#         google_user = user_info_response.json()
        
#         # Here you would need to create/update user in Cognito
#         # This is more complex and requires admin API calls
        
#         return {
#             "message": "Direct Google authentication successful",
#             "google_user": google_user,
#             "note": "This requires additional Cognito user creation/linking"
#         }
    
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Direct Google callback failed: {str(e)}")

def generate_state() -> str:
        """Generate secure state parameter for OAuth"""
        return secrets.token_urlsafe(32)

@app.post("/auth/google/login", response_model=GoogleLoginInitResponse)
async def initiate_google_login():
    """
    Initiate Google OAuth login flow
    
    Returns a login URL that the frontend should redirect the user to.
    The user will authenticate with Google and be redirected back to your callback URL.
    """
    try:
        # Generate secure state parameter
        state = generate_state()
        
        # Build Cognito hosted UI URL with Google provider
        login_url = (
            f"https://{COGNITO_DOMAIN}/oauth2/authorize?"
            f"response_type=code&"
            f"client_id={COGNITO_CLIENT_ID}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"scope=email+openid+profile&"
            f"state={state}&"
            f"identity_provider=Google"
        )
        print("login url", login_url)
        
        # State expires in 10 minutes
        expires_at = datetime.now() + timedelta(minutes=10)
        
        print(f"Google login initiated with state: {state}")
        
        return GoogleLoginInitResponse(
            login_url=login_url,
            state=state,
            expires_at=expires_at
        )
    
    except Exception as e:
        print(f"Failed to initiate Google login: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to initiate Google login"
        )

@app.get("/auth/google/callback", response_model=TokenResponse)
async def handle_google_callback(
    code: str = Query(..., description="Authorization code from Google OAuth"),
    state: str = Query(..., description="State parameter for security")
):
    """
    Handle Google OAuth callback
    
    Exchange the authorization code for JWT tokens.
    This endpoint should be called by your frontend after the user
    is redirected back from Google authentication.
    """
    try:
        print(f"Processing Google callback with state: {state}")
        
        # Exchange authorization code for tokens
        token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"
        
        token_data = {
            "grant_type": "authorization_code",
            "client_id": COGNITO_CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI
        }
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        # Add client secret if configured
        if COGNITO_CLIENT_SECRET:
            credentials = base64.b64encode(
                f"{COGNITO_CLIENT_ID}:{COGNITO_CLIENT_SECRET}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"
        
        # Make token exchange request
        response = requests.post(token_url, data=token_data, headers=headers, timeout=10)
        
        if response.status_code != 200:
            print(f"Token exchange failed: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=400,
                detail="Failed to exchange authorization code for tokens"
            )
        
        tokens = response.json()
        
        # Validate token response
        required_tokens = ['access_token', 'id_token']
        missing_tokens = [token for token in required_tokens if token not in tokens]
        if missing_tokens:
            print(f"Missing tokens in response: {missing_tokens}")
            raise HTTPException(
                status_code=500,
                detail="Invalid token response from authentication service"
            )
        
        print("Google authentication successful")
        
        return TokenResponse(
            access_token=tokens['access_token'],
            id_token=tokens['id_token'],
            refresh_token=tokens.get('refresh_token'),
            expires_in=tokens.get('expires_in', 3600),
            scope=tokens.get('scope')
        )
    
    except HTTPException:
        raise
    except requests.RequestException as e:
        print(f"Network error during token exchange: {e}")
        raise HTTPException(
            status_code=503,
            detail="Authentication service temporarily unavailable"
        )
    except Exception as e:
        print(f"Unexpected error in Google callback: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error during authentication"
        )

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


#---------________------ ____________________________




class TokenData(BaseModel):
    access_token: str
    refresh_token: str = None

@app.post("/validate-and-revoke-google-token")
async def validate_and_revoke_google_token(token_data: TokenData):
    """
    POST endpoint that:
    1. Validates Google federated token using Cognito OAuth userInfo
    2. Revokes the token using Cognito OAuth revoke endpoint
    """
    
    result = google_validator.validate_and_revoke_google_token(
        access_token=token_data.access_token,
        refresh_token=token_data.refresh_token
    )
    
    if result["success"]:
        return {
            "message": "Token validated and revoked successfully",
            "user_info": {
                "username": result["validation"]["username"],
                "email": result["validation"]["userinfo"].get("email"),
                "name": result["validation"]["userinfo"].get("name")
            },
            "revocation_summary": {
                "tokens_revoked": len(result["revocation_results"]),
                "global_signout": result["global_signout"]["success"],
                "token_now_invalid": result["token_revoked"]
            },
            "security_status": result["security_status"],
            "details": result
        }
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "error": result["error"],
                "step_failed": result["step_failed"],
                "details": result
            }
        )

@app.post("/validate-google-token")
async def validate_google_token_only(token_data: dict):
    """
    POST endpoint to only validate Google federated token
    """
    
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="access_token required")
    
    result = google_validator._validate_token_via_userinfo(access_token)
    
    if result["is_valid"]:
        return {
            "message": "Token is valid",
            "user_info": result["userinfo"],
            "username": result["username"],
            "validation_method": result["validation_method"]
        }
    else:
        raise HTTPException(
            status_code=401,
            detail={
                "error": result["error"],
                "status_code": result.get("status_code"),
                "validation_method": result.get("validation_method")
            }
        )

@app.post("/revoke-google-token")
async def revoke_google_token_only(token_data: TokenData):
    """
    POST endpoint to only revoke Google federated token
    """
    
    revocation_results = []
    
    # Revoke access token
    access_result = google_validator._revoke_token_via_oauth(
        token_data.access_token, 
        "access_token"
    )
    revocation_results.append({"type": "access_token", "result": access_result})
    
    # Revoke refresh token if provided
    if token_data.refresh_token:
        refresh_result = google_validator._revoke_token_via_oauth(
            token_data.refresh_token,
            "refresh_token"
        )
        revocation_results.append({"type": "refresh_token", "result": refresh_result})
    
    # Check if any revocation succeeded
    success_count = sum(1 for r in revocation_results if r["result"]["success"])
    
    return {
        "message": f"Revocation completed: {success_count}/{len(revocation_results)} tokens revoked",
        "revocation_results": revocation_results,
        "overall_success": success_count > 0
    }


class GoogleTokenValidator:
    def __init__(self, user_pool_id: str, client_id: str, client_secret: str, region: str = 'us-east-1'):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region
        
        # Construct Cognito domain
        domain_prefix = user_pool_id.split('_')[0] + user_pool_id.split('_')[1]
        self.cognito_domain = f"https://{domain_prefix}.auth.{region}.amazoncognito.com"
        
        # OAuth endpoints
        self.userinfo_url = f"{self.cognito_domain}/oauth2/userInfo"
        self.revoke_url = f"{self.cognito_domain}/oauth2/revoke"
        self.token_url = f"{self.cognito_domain}/oauth2/token"
        
        self.cognito_client = boto3.client('cognito-idp', region_name=region)
    
    def validate_and_revoke_google_token(self, access_token: str, refresh_token: str = None) -> dict:
        """
        Complete flow: Validate Google federated token, then revoke it
        """
        
        # Step 1: Validate token using userInfo endpoint
        validation_result = self._validate_token_via_userinfo(access_token)
        
        if not validation_result["is_valid"]:
            return {
                "success": False,
                "error": "Token validation failed",
                "validation_error": validation_result["error"],
                "step_failed": "validation"
            }
        
        # Step 2: Revoke tokens
        revocation_results = []
        
        # Revoke access token
        access_revoke_result = self._revoke_token_via_oauth(access_token, "access_token")
        revocation_results.append({
            "token_type": "access_token",
            "result": access_revoke_result
        })
        
        # Revoke refresh token if provided
        if refresh_token:
            refresh_revoke_result = self._revoke_token_via_oauth(refresh_token, "refresh_token")
            revocation_results.append({
                "token_type": "refresh_token", 
                "result": refresh_revoke_result
            })
        
        # Step 3: Global sign out for extra security
        global_signout_result = self._global_signout(validation_result["username"])
        
        # Step 4: Verify revocation
        post_revoke_validation = self._validate_token_via_userinfo(access_token)
        
        return {
            "success": True,
            "validation": validation_result,
            "revocation_results": revocation_results,
            "global_signout": global_signout_result,
            "token_revoked": not post_revoke_validation["is_valid"],
            "post_revoke_error": post_revoke_validation.get("error"),
            "security_status": "Token successfully revoked" if not post_revoke_validation["is_valid"] else "Warning: Token may still be active"
        }
    
    def _validate_token_via_userinfo(self, access_token: str):
        """
        Validate token using Cognito's OAuth2 userInfo endpoint
        This works for Google federated tokens
        """
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(
                self.userinfo_url,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                userinfo = response.json()
                
                # Extract username from token for additional info
                try:
                    payload = jwt.decode(access_token, options={"verify_signature": False})
                    username = payload.get('username')
                except:
                    username = userinfo.get('cognito:username', 'unknown')
                
                return {
                    "is_valid": True,
                    "userinfo": userinfo,
                    "username": username,
                    "validation_method": "oauth_userinfo",
                    "status_code": 200
                }
            
            elif response.status_code == 401:
                return {
                    "is_valid": False,
                    "error": "Token is invalid or expired",
                    "status_code": 401,
                    "response_text": response.text
                }
            
            elif response.status_code == 403:
                return {
                    "is_valid": False,
                    "error": "Token doesn't have required scopes",
                    "status_code": 403,
                    "response_text": response.text
                }
            
            else:
                return {
                    "is_valid": False,
                    "error": f"Validation failed with status {response.status_code}",
                    "status_code": response.status_code,
                    "response_text": response.text
                }
        
        except requests.exceptions.RequestException as e:
            return {
                "is_valid": False,
                "error": f"Network error: {str(e)}",
                "validation_method": "oauth_userinfo"
            }
        
        except Exception as e:
            return {
                "is_valid": False,
                "error": f"Validation exception: {str(e)}",
                "validation_method": "oauth_userinfo"
            }
    
    def _revoke_token_via_oauth(self, token: str, token_type_hint: str):
        """
        Revoke token using Cognito's OAuth2 revoke endpoint
        """
        try:
            # Prepare Basic Auth credentials
            credentials = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            
            headers = {
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            data = {
                "token": token,
                "token_type_hint": token_type_hint
            }
            
            response = requests.post(
                self.revoke_url,
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "message": f"{token_type_hint} revoked successfully",
                    "status_code": 200
                }
            
            elif response.status_code == 400:
                return {
                    "success": False,
                    "error": "Bad request - invalid token or client",
                    "status_code": 400,
                    "response_text": response.text
                }
            
            elif response.status_code == 401:
                return {
                    "success": False,
                    "error": "Unauthorized - invalid client credentials",
                    "status_code": 401,
                    "response_text": response.text
                }
            
            else:
                return {
                    "success": False,
                    "error": f"Revocation failed with status {response.status_code}",
                    "status_code": response.status_code,
                    "response_text": response.text
                }
        
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Network error during revocation: {str(e)}"
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Revocation exception: {str(e)}"
            }
    
    def _global_signout(self, username: str):
        """
        Additional security: Global sign out using Cognito admin API
        """
        try:
            self.cognito_client.admin_user_global_sign_out(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            
            return {
                "success": True,
                "message": "Global sign out successful",
                "username": username
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Global sign out failed: {str(e)}",
                "username": username
            }

# Initialize validator
google_validator = GoogleTokenValidator(
    user_pool_id='us-east-1_y82Pz5saV',
    client_id='3ar31q7mrjph4ih4mgbueutjr5',
    client_secret='19rglnm2vtiu644ob2q9klb4c1rvthtap4bnhmrtrqe295j6re9m'
)
# _______________________________________________________

from typing import Dict, Any
import time

class GoogleFederatedTokenRefresher:
    def __init__(self, user_pool_id: str, client_id: str, client_secret: str, region: str = 'us-east-1'):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region
        self.cognito_client = boto3.client('cognito-idp', region_name=region)
        
        # Construct Cognito domain
        domain_prefix = user_pool_id.split('_')[0] + user_pool_id.split('_')[1]
        self.cognito_domain = f"https://{domain_prefix}.auth.{region}.amazoncognito.com"
        self.token_url = f"{self.cognito_domain}/oauth2/token"
    
    def refresh_google_federated_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh Google federated tokens using Cognito refresh token
        """
        
        try:
            # Method 1: Try OAuth2 token endpoint
            oauth_result = self._refresh_via_oauth2(refresh_token)
            
            if oauth_result["success"]:
                return oauth_result
            print("OAuth2 refresh failed, trying Cognito API...")
            # Method 2: Fallback to Cognito API
            print("OAuth2 refresh failed, trying Cognito API...")
            api_result = self._refresh_via_cognito_api(refresh_token)
            
            return api_result
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Token refresh failed: {str(e)}",
                "method": "exception"
            }
    
    def _refresh_via_oauth2(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh tokens using OAuth2 token endpoint"""
        
        try:
            # Prepare Basic Auth credentials
            credentials = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            
            headers = {
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }
            
            response = requests.post(
                self.token_url,
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                tokens = response.json()
                
                # Analyze the new tokens
                token_info = self._analyze_tokens(tokens)
                
                return {
                    "success": True,
                    "method": "oauth2_token_endpoint",
                    "tokens": {
                        "access_token": tokens["access_token"],
                        "id_token": tokens.get("id_token"),
                        "refresh_token": tokens.get("refresh_token", refresh_token),  # May or may not get new refresh token
                        "token_type": tokens.get("token_type", "Bearer"),
                        "expires_in": tokens.get("expires_in", 3600)
                    },
                    "token_info": token_info,
                    "expires_at": int(time.time()) + tokens.get("expires_in", 3600)
                }
            
            elif response.status_code == 400:
                error_data = response.json()
                return {
                    "success": False,
                    "error": error_data.get("error", "Bad request"),
                    "error_description": error_data.get("error_description", "Invalid refresh token"),
                    "method": "oauth2_token_endpoint",
                    "status_code": 400
                }
            
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}",
                    "response_text": response.text,
                    "method": "oauth2_token_endpoint"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"OAuth2 refresh exception: {str(e)}",
                "method": "oauth2_token_endpoint"
            }
    
    def _refresh_via_cognito_api(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh tokens using Cognito InitiateAuth API"""
        
        try:
            response = self.cognito_client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'REFRESH_TOKEN': refresh_token
                }
            )
            
            auth_result = response.get('AuthenticationResult')
            
            if auth_result:
                # Analyze the new tokens
                token_info = self._analyze_tokens(auth_result)
                
                return {
                    "success": True,
                    "method": "cognito_initiate_auth",
                    "tokens": {
                        "access_token": auth_result['AccessToken'],
                        "id_token": auth_result.get('IdToken'),
                        "refresh_token": auth_result.get('RefreshToken', refresh_token),
                        "token_type": auth_result.get('TokenType', 'Bearer'),
                        "expires_in": auth_result.get('ExpiresIn', 3600)
                    },
                    "token_info": token_info,
                    "expires_at": int(time.time()) + auth_result.get('ExpiresIn', 3600)
                }
            else:
                return {
                    "success": False,
                    "error": "No AuthenticationResult in response",
                    "method": "cognito_initiate_auth",
                    "challenge": response.get('ChallengeName')
                }
        
        except self.cognito_client.exceptions.NotAuthorizedException:
            return {
                "success": False,
                "error": "Refresh token is invalid or expired",
                "method": "cognito_initiate_auth",
                "error_code": "NOT_AUTHORIZED"
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Cognito API refresh exception: {str(e)}",
                "method": "cognito_initiate_auth"
            }
    
    def _analyze_tokens(self, tokens: Dict) -> Dict[str, Any]:
        """Analyze token information"""
        
        try:
            access_token = tokens.get('access_token') or tokens.get('AccessToken')
            
            if access_token:
                payload = jwt.decode(access_token, options={"verify_signature": False})
                
                return {
                    "username": payload.get('username'),
                    "scope": payload.get('scope'),
                    "token_use": payload.get('token_use'),
                    "exp": payload.get('exp'),
                    "iat": payload.get('iat'),
                    "is_federated": 'Google_' in payload.get('username', ''),
                    "client_id": payload.get('client_id')
                }
        
        except Exception as e:
            return {"analysis_error": str(e)}
        
        return {}
    
    def auto_refresh_if_needed(self, access_token: str, refresh_token: str, buffer_minutes: int = 5) -> Dict[str, Any]:
        """
        Automatically refresh token if it's about to expire
        """
        
        try:
            # Check if token is about to expire
            payload = jwt.decode(access_token, options={"verify_signature": False})
            exp_timestamp = payload.get('exp', 0)
            current_timestamp = int(time.time())
            
            # Calculate time until expiration
            time_until_expiry = exp_timestamp - current_timestamp
            buffer_seconds = buffer_minutes * 60
            
            if time_until_expiry <= buffer_seconds:
                print(f"Token expires in {time_until_expiry} seconds, refreshing...")
                return self.refresh_google_federated_tokens(refresh_token)
            else:
                print(f"Token is still valid for {time_until_expiry} seconds")
                return {
                    "success": True,
                    "action": "no_refresh_needed",
                    "time_until_expiry": time_until_expiry,
                    "current_token": access_token
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Auto-refresh check failed: {str(e)}"
            }

# Initialize token refresher
token_refresher = GoogleFederatedTokenRefresher(
    user_pool_id='us-east-1_y82Pz5saV',
    client_id='3ar31q7mrjph4ih4mgbueutjr5',
    client_secret='19rglnm2vtiu644ob2q9klb4c1rvthtap4bnhmrtrqe295j6re9m'
)




class RefreshRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    id_token: str = None
    refresh_token: str = None
    expires_in: int
    token_type: str = "Bearer"

@app.post("/refresh-google-tokens", response_model=TokenResponse)
async def refresh_google_tokens(request: RefreshRequest):
    """
    Refresh Google federated tokens using Cognito refresh token
    """
    
    result = token_refresher.refresh_google_federated_tokens(request.refresh_token)
    
    if result["success"]:
        tokens = result["tokens"]
        return TokenResponse(
            access_token=tokens["access_token"],
            id_token=tokens.get("id_token"),
            refresh_token=tokens.get("refresh_token"),
            expires_in=tokens["expires_in"],
            token_type=tokens["token_type"]
        )
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "error": result["error"],
                "method": result.get("method"),
                "error_code": result.get("error_code")
            }
        )
    
# --- The endpoint ---
@app.post("/change-group")
def change_group_to_admin(
    body: ChangeGroupRequest):
    """
    Move a user into a target group (default: 'Admins'). Optionally remove from all other groups.
    Requires the caller to be in 'Admins'.
    """
    try:
        # Optionally remove user from all other groups first
        if body.remove_from_all_other_groups:
            listed = cognito_client.admin_list_groups_for_user(
                UserPoolId=COGNITO_USER_POOL_ID,
                Username=body.username
            )
            current_groups = [g["GroupName"] for g in listed.get("Groups", [])]

            for g in current_groups:
                if g != body.target_group:
                    cognito_client.admin_remove_user_from_group(
                        UserPoolId=COGNITO_USER_POOL_ID,
                        Username=body.username,
                        GroupName=g
                    )

        # Ensure user is added to the target group
        cognito_client.admin_add_user_to_group(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=body.username,
            GroupName=body.target_group
        )

        return {
            "message": f"User '{body.username}' is now in '{body.target_group}'",
            "removed_other_groups": body.remove_from_all_other_groups
        }

    except cognito_client.exceptions.UserNotFoundException:
        raise HTTPException(status_code=404, detail="User not found")
    except cognito_client.exceptions.ResourceNotFoundException as e:
        raise HTTPException(status_code=404, detail=f"Group not found: {e}")
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=403, detail="Not authorized to modify groups")
    except cognito_client.exceptions.TooManyRequestsException:
        raise HTTPException(status_code=429, detail="Too many requests to Cognito")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to change group: {e}")
