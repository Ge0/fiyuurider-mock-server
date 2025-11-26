# app.py
# Minimal Flask skeleton for an OAuth2-like auth endpoint that redirects to a custom deeplink.
# Comments in English as you prefer.

from flask import Flask, request, redirect, jsonify
from urllib.parse import urlencode
import secrets

app = Flask(__name__)

DEEPLINK_CALLBACK = "com.fiyuuriders.app://oauth2/callback"

@app.get("/oauth2/auth")
def oauth2_auth():
    """
    GET /foobarbtr/oauth2/auth
    Mimics an OAuth2 authorization endpoint then redirects to the mobile app deeplink.

    Typical incoming params might include:
      - client_id, redirect_uri, response_type, scope, state, nonce, etc.
    We only care about returning:
      - code (authorization code)
      - state (echoed back if provided)
    """

    # Echo state back if it exists (standard OAuth2 / OIDC behavior)
    state = request.args.get("state")

    # Allow caller to provide a code for testing; otherwise generate a fake one.
    code = request.args.get("code") or secrets.token_urlsafe(24)

    # Build callback query
    callback_params = {"code": code}
    if state is not None:
        callback_params["state"] = state

    redirect_url = f"{DEEPLINK_CALLBACK}?{urlencode(callback_params)}"
    return redirect(redirect_url, code=302)


@app.route("/oauth2/token", methods=["POST"])
def token():
    print(request.form)
    # breakpoint()
    # if request.form["grant_type"] == "authorization_code":
    if True:
        return jsonify({
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXl1cmlkZXJzIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMzYwMCwic2NvcGUiOiJvZmZsaW5lIG9wZW5pZCBvZmZsaW5lX2FjY2VzcyJ9.signed_token_here_1234567890abcdef",
            "refresh_token": "def50200e3b2c8d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
            "token_type": "Bearer",
            "expires_in": 3600,
            "expires_timestamp": 99999999999,
            "scope": "offline openid offline_access"
        })
    elif request.form["grant_type"] == "refresh_token":
        return jsonify({
            "refresh_token": "def50200e3b2c8d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
            "expires_timestamp": 99999999999,
            "scope": "offline openid offline_access"
        })        

"""
192.168.1.43 - - [26/Nov/2025 21:01:13] "GET /v1/utils/feature-flags HTTP/1.1" 404 -
192.168.1.43 - - [26/Nov/2025 21:03:48] "GET /v1/riders/triptracker/rider HTTP/1.1" 404 -
192.168.1.43 - - [26/Nov/2025 21:03:48] "GET /v1/riders/info HTTP/1.1" 404 -
"""

@app.route("/v1/utils/feature-flags")
def feature_flags():
    print(request.headers)
    return jsonify([
    {
        "flagName": "ALOTECH_WEBCHAT",
        "active": True
    },
    {
       "flagName": "ALOTECH_START_CALL",
       "active": True,
    },
    {
        "flagName": "TRENDYOL_6_DIGITS_OTP",
        "active": False,
    },
    {
        "flagName": "ALOTECH_START_IVR_CALL",
        "active": False
    }])


@app.route("/v1/riders/triptracker/rider")
def rider():
    print(request.headers)
    return jsonify({
        "data": {
            "externalId": "xxx",
            "msidn": "5031231337",
            "name": "Geoffrey",
        }
    })


@app.route("/v1/riders/info")
def riders_info():
    print(request.headers)
    return jsonify({
        "data": {
            "username": "Kaan",
            
            "lockType": "xxx", 
            "posList": [
                {
                    "posDeviceId": "xxx",
                }
            ]
        }
    })

@app.route("/v1/reconciliation/locker/info/2")
def reconciliation():
    print(request.headers)
    return jsonify(
        {
            "type": "GET_ORDER_LOCKER_SUCCESS",
            "orderLocker": {

            }
        }
    )


@app.route("/v1/riders/shift")
def shift():
    print(request.headers)
    return jsonify(
        {
            "header": {
                "detailCode": "NO_ACTIVE_SHIFT",
                "message": "Aucun shift actif trouvé"
            },
            "data": None
        }
    )

@app.route("/v1/notifications/device", methods=["POST"])
def device():
    print(request.json)
    return jsonify({
        "deviceInfo": {
            "id": 123,
            "dvToken": request.json.get("dvToken"),
            "dvId": request.json.get("dvId"), 
            "dvName": request.json.get("dvName"),
            "dvOs": request.json.get("dvOs"),
            "riderId": 456,
            "isActive": True,
            "createdAt": "2024-01-01T00:00:00.000Z",
            "updatedAt": "2024-01-01T00:00:00.000Z"
        }
        })


@app.route("/v1/riders/deviceInfo", methods=["POST"])
def device_info():
    print(request.json)
    return jsonify({
        "deviceInfo": {
            "id": 123,
            "deviceToken": "xxx",
            "deviceId": "xxx", 
            "deviceOs": "android",
            "deviceName": "string",
            "riderId": 456,
            "isActive": True,
            "createdAt": "2024-01-01T00:00:00.000Z",
            "updatedAt": "2024-01-01T00:00:00.000Z"
        }
    })


if __name__ == "__main__":
    # For local dev only. Use gunicorn/uwsgi in production.
    app.run(host="0.0.0.0", port=3000, debug=True)
