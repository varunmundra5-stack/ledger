from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx


@dataclass(frozen=True)
class ResolvedCredential:
    value: str
    version: str


class CredentialBindingError(RuntimeError):
    pass


class CredentialNeedsReauthentication(CredentialBindingError):
    pass


class CredentialSyncError(CredentialBindingError):
    pass


class CredentialConflict(CredentialSyncError):
    pass


class VersionedCredentialBinding(Protocol):
    async def load(self) -> ResolvedCredential: ...

    async def replace(self, expected_version: str, value: str) -> str: ...


class HttpVersionedCredentialBinding:
    def __init__(
        self,
        url: str,
        headers: dict[str, str],
        *,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url
        self.headers = dict(headers)
        self.timeout = timeout
        self.transport = transport

    async def load(self) -> ResolvedCredential:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.get(self.url, headers=self.headers)
        except httpx.RequestError as exc:
            raise CredentialSyncError("Credential source is unavailable.") from exc
        self._raise_for_status(response)
        try:
            payload = response.json()
            value = payload["value"]
            version = payload["version"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CredentialSyncError(
                "Credential source returned an invalid response."
            ) from exc
        if not isinstance(value, str) or not isinstance(version, str) or not version:
            raise CredentialSyncError("Credential source returned an invalid response.")
        return ResolvedCredential(value=value, version=version)

    async def replace(self, expected_version: str, value: str) -> str:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.put(
                    self.url,
                    headers=self.headers,
                    json={"expected_version": expected_version, "value": value},
                )
        except httpx.RequestError as exc:
            raise CredentialSyncError("Credential update is unavailable.") from exc
        self._raise_for_status(response)
        try:
            version = response.json()["version"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CredentialSyncError(
                "Credential source returned an invalid response."
            ) from exc
        if not isinstance(version, str) or not version:
            raise CredentialSyncError("Credential source returned an invalid response.")
        return version

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code == 404:
            raise CredentialNeedsReauthentication(
                "ChatGPT authentication is missing. Please sign in again."
            )
        if response.status_code == 409:
            raise CredentialConflict(
                "The canonical credential changed in another runtime."
            )
        if response.status_code in (400, 422):
            raise CredentialNeedsReauthentication(
                "ChatGPT authentication is invalid. Please sign in again."
            )
        if response.status_code in (401, 403):
            raise CredentialSyncError("Credential authorization was rejected.")
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise CredentialSyncError("Credential source request failed.") from exc
