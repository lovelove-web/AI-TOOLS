# Add to your project's settings.py

INSTALLED_APPS = [
    # ...existing apps...
    "menu",
]

# Get these from https://dashboard.stripe.com/test/apikeys (use the TEST keys while developing)
STRIPE_SECRET_KEY = "sk_test_your_secret_key_here"
STRIPE_PUBLISHABLE_KEY = "pk_test_your_publishable_key_here"

# Better practice: load from environment instead of hardcoding
# import os
# STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
