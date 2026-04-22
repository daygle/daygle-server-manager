from passlib.context import CryptContext

pwd_context = CryptContext(
    # bcrypt_sha256 pre-hashes input, avoiding bcrypt's 72-byte input limit.
    # Keep bcrypt second so previously stored bcrypt hashes still verify.
    schemes=["bcrypt_sha256", "bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)
