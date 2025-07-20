import secrets
from django.core.management.utils import get_random_secret_key

def prompt(label):
    value = input(f"{label} (optional, press Enter to leave blank): ")
    return value.strip() or ""

def generate_env():
    print("🛠  Generating .env file...")

    # --- Inputs from user ---
    db_name = prompt("Database name")
    db_user = prompt("Database user")
    db_pass = prompt("Database password")

    print("\n⚠️  If you leave the following email field empty, emails will only appear in the console (safe for testing).")
    email_host_user = prompt("Email host user (e.g., yourname@gmail.com)")
    email_host_password = prompt("Email host password")

    # --- Auto-generated secrets ---
    django_secret = get_random_secret_key()
    itd_secret = secrets.token_urlsafe(32)
    email_confirm_salt = secrets.token_urlsafe(32)
    email_change_salt = secrets.token_urlsafe(32)
    reset_password_salt = secrets.token_urlsafe(32)

    # --- Email backend logic ---
    if email_host_user and email_host_password:
        email_backend = "django.core.mail.backends.smtp.EmailBackend"
    else:
        email_backend = "django.core.mail.backends.console.EmailBackend"

    # --- Redis values (default) ---
    redis_host = "127.0.0.1"
    redis_port = "6379"
    redis_db = "1"

    # --- Write to .env ---
    env_content = f"""# Django
DJANGO_SECRET_KEY={django_secret}

# PostgreSQL
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME={db_name}
DATABASE_USER={db_user}
DATABASE_PASSWORD={db_pass}

# Redis
REDIS_HOST={redis_host}
REDIS_PORT={redis_port}
REDIS_DB={redis_db}
REDIS_USER=
REDIS_PASSWORD=

# ITD secrets
ITD_SECRET_KEY={itd_secret}
ITD_EMAIL_CONFIRM_SALT={email_confirm_salt}
ITD_EMAIL_CHANGE_SALT={email_change_salt}
ITD_RESET_PASSWORD_SALT={reset_password_salt}

# Email settings
EMAIL_BACKEND={email_backend}
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER={email_host_user}
EMAIL_HOST_PASSWORD={email_host_password}
"""

    with open(".env", "w") as f:
        f.write(env_content)

    print("\n✅ .env file generated successfully!")

if __name__ == "__main__":
    generate_env()
