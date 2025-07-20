# Shortify

Shortify is a modern, Django-based URL shortener service offering a RESTful API via Django REST Framework. Users can create, manage, and share shortened links with advanced features like password protection, expiration dates, and detailed visit analytics.
The project uses JWT authentication, supports email verification and change, and utilizes Redis for secure token blacklisting.

## 🚀 Features

- Create short links for authenticated and anonymous users
- Set password protection for short links (authenticated users only)
- Automatic expiration (12 hours for anonymous users, 30 days for authenticated users)
- Track visit counts for each link
- Manage links (list, update, delete)
- JWT authentication and token blacklisting with Redis
- Email confirmation and email change functionality
- Password change and account deletion endpoints
- Admin panel for user and link management

## 📁 Project Structure

```
Shortify/
    accounts/
        models.py
        views.py
        serializers.py
        ...
    shortener/
        models.py
        views.py
        serializers.py
        ...
    templates/
    manage.py
    requirements.txt
    ...
```

## ⚙️ Installation

1. Clone the repository:
```sh
git clone https://github.com/rezaxanii/shortify.git
cd shortify
```

2. Create and activate a virtual environment:
```sh
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```sh
pip install -r requirements.txt
```

4. Generate the .env file:
```sh
python setup_env.py
```

This script will guide you through creating the required .env file.
You can skip inputs (by pressing Enter) to leave values empty.
For testing purposes, leave email settings blank to use Django’s console email backend.

5. Run migrations:
```sh
python manage.py migrate
```

6. Start the development server:
```sh
python manage.py runserver
```

## 🧪 Testing

To run tests:
```sh
python manage.py test
```
You can also run specific app tests:
```sh
python manage.py test accounts
python manage.py test shortener
```
Test coverage includes user registration, login, email confirmation, link creation, update, deletion, and token management.

## 📡 API Usage

### ➕ Create a short link
```
POST /url/create/
{
    "url": "https://example.com",
    "password": "optional"  # Only for authenticated users
}
```

### 📜 List user's links
```
GET /url/list/
```

### 🔍 Get link details
```
GET /url/detail/<id>
```

### ✏️ Update a link
```
PATCH /url/update/<id>/
{
    "url": "https://new-url.com"
}
```

### ❌ Delete a link
```
DELETE /url/delete/<id>/
```

### ↪️ Redirect to original URL
```
GET /url/<short_code>/?password=optional
```

### 👤 User Registration
```
POST /accounts/register/
{
    "username": "yourusername",
    "email": "your@email.com",
    "password": "YourPassword123!"
}
```

### 🔐 User Login
```
POST /accounts/login/
{
    "username": "yourusername",
    "password": "YourPassword123!"
}
```

### ✅ Email Confirmation
```
GET /accounts/confirm-email/<token>/
```

### 🔁 Change Email
```
POST /accounts/change-email/
{
    "new_email": "new@email.com"
}
```

### 🔁 Change Password
```
POST /accounts/change-password/
{
    "email": "your@email.com"
}
```

### 🗑️ Delete Account
```
DELETE /accounts/delete/
```

## 📝 License

This project is licensed under the [MIT License](LICENSE).
---

For more details, see [accounts/views.py](accounts/views.py), [shortener/views.py](shortener/views.py), and [Shortify/settings.py](Shortify/settings.py).