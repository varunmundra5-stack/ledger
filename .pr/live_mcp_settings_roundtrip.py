from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import threading
import time

from fastmcp import FastMCP

from openhands.sdk.mcp import create_mcp_tools
from openhands.sdk.mcp.config import dump_mcp_config
from openhands.sdk.settings.model import (
    AGENT_SETTINGS_SCHEMA_VERSION,
    OpenHandsAgentSettings,
    validate_agent_settings,
)


EVIDENCE_SECRET = "pr4013-preserved-header-value"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_server(port: int) -> None:
    mcp = FastMCP("pr4013-live-migration")

    @mcp.tool()
    def echo_migrated(message: str) -> str:
        """Return a marker proving the migrated server was invoked."""
        return f"migrated-mcp-ok:{message}"

    def run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            mcp.run_http_async(
                host="127.0.0.1",
                port=port,
                transport="http",
                show_banner=False,
                path="/mcp",
            )
        )

    threading.Thread(target=run, daemon=True, name="pr4013-mcp").start()
    time.sleep(0.75)


def main() -> None:
    port = free_port()
    start_server(port)
    legacy_fixture = {
        "schema_version": 4,
        "agent_kind": "openhands",
        "llm": {"model": "openhands/gpt-5.5"},
        "mcp_config": {
            "mcpServers": {
                "local-echo": {
                    "url": f"http://127.0.0.1:{port}/mcp",
                    "transport": "http",
                    "headers": {"X-Evidence-Token": EVIDENCE_SECRET},
                }
            }
        },
    }

    loaded = validate_agent_settings(legacy_fixture)
    assert isinstance(loaded, OpenHandsAgentSettings)
    loaded_servers = dump_mcp_config(loaded.mcp_config)
    header = loaded_servers["local-echo"]["headers"]["X-Evidence-Token"]
    print(
        json.dumps(
            {
                "phase": "legacy-load",
                "sdk_schema_version": AGENT_SETTINGS_SCHEMA_VERSION,
                "loaded_schema_version": loaded.schema_version,
                "server_names": sorted(loaded_servers),
                "header_fingerprint": fingerprint(header),
            },
            sort_keys=True,
        )
    )

    persisted = loaded.model_dump(
        mode="json",
        context={"expose_secrets": True},
        exclude_none=True,
        exclude_defaults=False,
    )
    restored = validate_agent_settings(persisted)
    restored_servers = dump_mcp_config(restored.mcp_config)
    restored_header = restored_servers["local-echo"]["headers"]["X-Evidence-Token"]
    print(
        json.dumps(
            {
                "phase": "save-and-reload",
                "saved_schema_version": persisted["schema_version"],
                "reloaded_schema_version": restored.schema_version,
                "server_names": sorted(restored_servers),
                "has_legacy_wrapper": "mcpServers" in restored_servers,
                "header_fingerprint": fingerprint(restored_header),
            },
            sort_keys=True,
        )
    )

    if AGENT_SETTINGS_SCHEMA_VERSION < 5:
        print(
            json.dumps(
                {
                    "phase": "migration-failure",
                    "reason": "current SDK has no v4-to-v5 persisted migration",
                    "expected_schema_version": 5,
                    "actual_schema_version": loaded.schema_version,
                    "mcp_start_attempted": False,
                },
                sort_keys=True,
            )
        )
        raise SystemExit(2)

    assert restored.schema_version == 5
    assert restored_header == EVIDENCE_SECRET
    assert "mcpServers" not in restored_servers

    with create_mcp_tools(restored.mcp_config, timeout=15.0) as client:
        names = sorted(tool.name for tool in client)
        tool = next(tool for tool in client if tool.name == "echo_migrated")
        action = tool.action_from_arguments({"message": "after-v5-reload"})
        result = tool.executor(action)
        assert "migrated-mcp-ok:after-v5-reload" in result.text

    print(
        json.dumps(
            {
                "phase": "migration-and-mcp-success",
                "saved_schema_version": persisted["schema_version"],
                "server_names": sorted(restored_servers),
                "has_legacy_wrapper": "mcpServers" in restored_servers,
                "header_fingerprint": fingerprint(restored_header),
                "tool_names": names,
                "tool_result": "migrated-mcp-ok:after-v5-reload",
                "client_closed": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
