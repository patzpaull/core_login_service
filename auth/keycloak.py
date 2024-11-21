
from keycloak import KeycloakOpenID
import os

KEYCLOAK_SERVER_URL = os.getenv(
    "KEYCLOAK_SERVER_URL", "https://sso.schoolmate.co.tz/")
REDIRECT_URI = os.getenv(
    "REDIRECT_URI", "https://core.schoolmate.co.tz/auth/callback")
REALM_NAME = os.getenv("REALM_NAME", "marketplace")
CLIENT_ID = os.getenv("CLIENT_ID", "mala")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "hzDJ9YmFUD51TqZa4gzUx9w3wuHneFCK")
# REALM_NAME = os.getenv("REALM_NAME", "schoolmate")
# CLIENT_ID_SUB = os.getenv("CLIENT_ID_SUB", "schoolmatey")
# CLIENT_SECRET_SUB = os.getenv(
# "CLIENT_SECRET_SUB", "AgayUdtqAiAhSGWrTnspohO6r8XXPuxk")


def get_keycloak_client(realm: str, client_id: str, client_secret: str) -> KeycloakOpenID:
    keycloak = KeycloakOpenID(
        server_url=KEYCLOAK_SERVER_URL,
        client_id=CLIENT_ID,
        client_secret_key=CLIENT_SECRET,
        realm_name=REALM_NAME,
        verify=True  # Ensure SSL verification in production
    )
    return keycloak
