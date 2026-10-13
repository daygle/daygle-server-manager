from __future__ import annotations

import base64
import logging
import socket

import paramiko
from sqlalchemy.exc import IntegrityError

from .database import SessionLocal
from .models import SSHHostKey

logger = logging.getLogger(__name__)


def host_key_name(host: str, port: int) -> str:
    """Return the known_hosts style lookup name paramiko uses for host/port."""
    return host if int(port) == 22 else f"[{host}]:{port}"


class TrustOnFirstUseHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Record a host's key the first time it is seen; later connections must present the same key.

    Keys already stored are loaded into the client before connecting, so paramiko itself raises
    BadHostKeyException when a known host presents a different key.
    """

    def missing_host_key(self, client, hostname, key):
        db = SessionLocal()
        try:
            db.add(SSHHostKey(hostname=hostname, key_type=key.get_name(), key_data=key.get_base64()))
            db.commit()
            logger.info("Trusted new SSH host key for %s (%s %s)", hostname, key.get_name(), key.fingerprint)
        except IntegrityError:
            # Another connection stored a key for this host concurrently; it must match.
            db.rollback()
            stored = (
                db.query(SSHHostKey)
                .filter(SSHHostKey.hostname == hostname, SSHHostKey.key_type == key.get_name())
                .first()
            )
            if stored is None or stored.key_data != key.get_base64():
                expected = _to_pkey(stored) if stored else key
                raise paramiko.BadHostKeyException(hostname, key, expected)
        finally:
            db.close()
        client.get_host_keys().add(hostname, key.get_name(), key)


def _to_pkey(row: SSHHostKey) -> paramiko.PKey:
    return paramiko.PKey.from_type_string(row.key_type, base64.b64decode(row.key_data))


def create_ssh_client() -> paramiko.SSHClient:
    """Create an SSHClient that verifies host keys against the keys stored in the database."""
    client = paramiko.SSHClient()
    host_keys = client.get_host_keys()
    db = SessionLocal()
    try:
        for row in db.query(SSHHostKey).all():
            try:
                host_keys.add(row.hostname, row.key_type, _to_pkey(row))
            except Exception:
                logger.warning("Ignoring unreadable stored SSH host key for %s", row.hostname)
    finally:
        db.close()
    client.set_missing_host_key_policy(TrustOnFirstUseHostKeyPolicy())
    return client


def forget_host_keys(db, host: str, port: int) -> int:
    """Delete stored host keys for host/port so the next connection trusts the presented key."""
    deleted = (
        db.query(SSHHostKey)
        .filter(SSHHostKey.hostname == host_key_name(host, port))
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted


def describe_ssh_error(exc: Exception) -> str:
    """Map an SSH connection exception to a message that is safe to show to users."""
    if isinstance(exc, paramiko.BadHostKeyException):
        return (
            f"Host key verification failed for {exc.hostname}: the server presented a different key than the "
            "one previously trusted. If the server was reinstalled or its keys were regenerated, use "
            "\"Reset Host Key\" when editing the server."
        )
    if isinstance(exc, paramiko.AuthenticationException):
        return "Authentication failed. Check username and credentials."
    if isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
        return "Unable to connect: connection refused or host unreachable."
    if isinstance(exc, socket.gaierror):
        return "Unable to resolve host name."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Connection timed out."
    if isinstance(exc, paramiko.SSHException):
        return "SSH negotiation failed."
    if isinstance(exc, OSError):
        return "Network error while connecting."
    return "Unexpected error while connecting."
