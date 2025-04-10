# Configuration settings (e.g., JWT secrets, Auth0 domain)

import os

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "dev-ojcu5tu8grh83473.us.auth0.com")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://dev-ojcu5tu8grh83473.us.auth0.com/api/v2/")
M2M_CLIENT_ID = os.getenv("M2M_CLIENT_ID", "3nqlZAqcqmKsyzW2br3xNIORurEKyX4L")
ALGORITHMS = ["RS256"]
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
SECRET_KEY = os.getenv("SECRET_KEY", "Some Secret key")
ALGORITHM = "HS256"