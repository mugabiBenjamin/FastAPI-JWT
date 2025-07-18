# fastapi-jwt

## Installation

```bash
uv sync
```

## Usage

```bash
source .venv/bin/activate

uv run uvicorn main:app --reload

# OR traditional
uvicorn main:app --reload
```

## Project Structure

```plaintext
└── FastAPI-JWT/
    ├─ __pycache__/
    ├─ .venv/
    ├─ .env
    ├─ .gitignore
    ├─ .python-version
    ├─ auth.py
    ├─ database.py
    ├─ main.py
    ├─ models.py
    ├─ pyproject.toml
    ├─ README.md
    ├─ todosapp.db
    └─ uv.lock
```

## Environment Variables

Create a `.env` file and add the following environment variables:

```env
# JWT Configuration
SECRET_KEY=your-secret-key
ALGORITHM=HS256

# Database Configuration
DATABASE_URL=sqlite:///./dbname.db
# For PostgreSQL: postgresql://username:password@localhost/dbname
# For MySQL: mysql://username:password@localhost/dbname
```

## Generate a Secret Key

```bash
python -c "import secrets; print(secrets.token_hex(32))"

# Or use the OpenSSL command:
openssl rand -hex 32

# Both generate a 32-byte hex string. Copy the output and use it as your SECRET_KEY in the auth file.
```

## Note -> `bcrypt 4.3.0+` has breaking changes with passlib
