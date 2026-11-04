"""The plain-HTTP transport, against a fake server that speaks it.

Kept separate from ``test_opamp_e2e`` because these assertions are about the
transport contract — statuses, headers, framing — and need no osqueryd.
"""

from __future__ import annotations

import uuid

import pytest

from osquery_opamp.opamp import transport as transport_module
from osquery_opamp.opamp.client import OpampClient
from osquery_opamp.opamp.pb import opamp
from osquery_opamp.opamp.transport import (
    HttpTransport,
    TransportError,
    WebSocketTransport,
    transport_for_url,
)

from fake_opamp_server import FakeHttpOpampServer

UID = bytes.fromhex("00112233445566778899aabbccddeeff")


def an_agent_message(**kwargs):
    return opamp.AgentToServer(instance_uid=kwargs.pop("instance_uid", UID), **kwargs)


@pytest.fixture
def server():
    with FakeHttpOpampServer() as fake:
        yield fake


def roundtrip(server, payload=None, **options):
    """Send one message and read the reply that answered it."""
    transport = HttpTransport(server.url, timeout=2.0, **options)
    transport.connect()
    try:
        transport.send((payload or an_agent_message()).SerializeToString())
        reply = transport.receive(timeout=2.0)
        assert reply is not None, "the transport dropped a reply it had already received"
        message = opamp.ServerToAgent()
        message.ParseFromString(reply)
        return message, transport
    finally:
        transport.close()


# -- the happy path ----------------------------------------------------------


def test_posts_the_message_and_returns_the_reply(server):
    message, _ = roundtrip(server)

    assert message.capabilities & opamp.ServerCapabilities_AcceptsStatus
    received = server.messages()
    assert len(received) == 1
    assert received[0].instance_uid == UID, "the body was not the message we sent"


def test_receive_times_out_instead_of_blocking(server):
    """A poll with nothing to say must return None, not hang: the client turns
    that into a heartbeat."""
    transport = HttpTransport(server.url, timeout=2.0)
    transport.connect()
    transport.send(an_agent_message().SerializeToString())
    transport.receive(timeout=2.0)

    assert transport.receive(timeout=0.2) is None


def test_close_drops_undelivered_replies(server):
    """A reply read after a reconnect would be answered twice, with a stale uid."""
    transport = HttpTransport(server.url, timeout=2.0)
    transport.connect()
    transport.send(an_agent_message().SerializeToString())
    transport.close()

    assert transport.receive(timeout=0.2) is None


# -- headers ----------------------------------------------------------------


def test_extra_headers_are_sent_on_every_request(server):
    roundtrip(server, headers=["Authorization: Bearer opamp_agent_test"])

    assert server.header_of("Authorization") == "Bearer opamp_agent_test"
    assert server.header_of("Content-Type") == "application/x-protobuf"


def test_instance_uid_header_is_the_canonical_uuid(server):
    """Server-side log lines name the agent by this header (#76); a non-canonical
    form makes its cross-check report a mismatch on every single request."""
    roundtrip(server, instance_uid=lambda: UID)

    assert server.header_of("OpAMP-Instance-UID") == str(uuid.UUID(bytes=UID))


def test_instance_uid_is_read_per_request(server):
    """The server can replace the uid mid-run, so the header must be a callable
    rather than a value captured at construction."""
    seen = [UID]
    transport = HttpTransport(server.url, timeout=2.0, instance_uid=lambda: seen[0])
    transport.connect()
    transport.send(an_agent_message().SerializeToString())
    transport.receive(timeout=2.0)

    replacement = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    seen[0] = replacement
    transport.send(an_agent_message(instance_uid=replacement).SerializeToString())
    transport.receive(timeout=2.0)
    transport.close()

    assert server.header_of("OpAMP-Instance-UID") == str(uuid.UUID(bytes=replacement))


def test_a_malformed_header_is_refused_before_any_request():
    with pytest.raises(ValueError, match="Name: Value"):
        HttpTransport("http://127.0.0.1:1/v1/opamp", headers=["nonsense"])


# -- refusals ---------------------------------------------------------------


def test_missing_credential_says_what_to_do(server):
    server.fail_next(401)

    with pytest.raises(TransportError) as caught:
        roundtrip(server)

    assert caught.value.status == 401
    assert "--header" in str(caught.value), "the error must name the fix, not just the status"


def test_a_bound_token_mismatch_is_explained(server):
    server.fail_next(403)

    with pytest.raises(TransportError) as caught:
        roundtrip(server)

    assert caught.value.status == 403
    assert "instance_uid" in str(caught.value)


def test_throttling_carries_the_servers_retry_after(server):
    """The server sheds load at the handshake and says when to come back; guessing
    at that interval is what turns a full server into a hammered one."""
    server.fail_next(503, {"Retry-After": "30"})

    with pytest.raises(TransportError) as caught:
        roundtrip(server)

    assert caught.value.status == 503
    assert caught.value.retry_after == 30.0


def test_two_requests_in_a_row_recover_after_a_refusal(server):
    """A refusal is not sticky: the next poll is a fresh, complete request."""
    server.fail_next(503)
    with pytest.raises(TransportError):
        roundtrip(server)

    message, _ = roundtrip(server)
    assert message.capabilities & opamp.ServerCapabilities_AcceptsStatus
    assert server.request_count == 2


def test_a_refused_body_still_reaches_the_agent(server):
    """400 carries a ServerToAgent explaining why. Dropping it would replace
    'your config is malformed' with 'HTTP 400'."""
    detail = opamp.ServerToAgent(
        error_response=opamp.ServerErrorResponse(
            type=opamp.ServerErrorResponseType_BadRequest,
            error_message="unsupported content_type",
        )
    )
    server.fail_next(400, body=detail.SerializeToString())

    message, _ = roundtrip(server)

    assert message.error_response.error_message == "unsupported content_type"


def test_a_400_with_no_body_is_still_an_error(server):
    server.fail_next(400)

    with pytest.raises(TransportError) as caught:
        roundtrip(server)

    assert caught.value.status == 400


def test_an_oversized_reply_is_refused_not_buffered(server, monkeypatch):
    monkeypatch.setattr(transport_module, "MAX_REPLY_BYTES", 1024)
    server.push_config({"options": {"padding": "x" * 8192}})

    with pytest.raises(TransportError, match="exceeds"):
        roundtrip(server)


# -- compression ------------------------------------------------------------


def test_gzipped_replies_are_decoded():
    with FakeHttpOpampServer(gzip_replies=True) as server:
        server.push_config({"schedule": {"gzipped": {"query": "select 1;", "interval": 60}}})
        message, _ = roundtrip(server)

    body = message.remote_config.config.config_map["osquery.json"].body
    assert b"gzipped" in body


def test_a_compression_bomb_is_refused_after_inflation(monkeypatch):
    """The ceiling has to hold after decompression, or a tiny reply fills memory."""
    monkeypatch.setattr(transport_module, "MAX_REPLY_BYTES", 4096)
    with FakeHttpOpampServer(gzip_replies=True) as server:
        server.push_config({"options": {"padding": "x" * 65536}})

        with pytest.raises(TransportError, match="decompressed"):
            roundtrip(server)


def test_corrupt_gzip_is_a_typed_error(server):
    with pytest.raises(TransportError, match="not valid gzip"):
        transport_module._gunzip(b"\x1f\x8bnot really gzip")


# -- construction -----------------------------------------------------------


def test_rejects_a_websocket_url():
    with pytest.raises(ValueError, match="http:// or https://"):
        HttpTransport("ws://127.0.0.1:4320/v1/opamp")


def test_hostname_override_is_refused_with_the_reason():
    with pytest.raises(ValueError, match="wss://"):
        HttpTransport("https://127.0.0.1:4320/v1/opamp", hostname="opamp.example.com")


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://127.0.0.1:4320/v1/opamp", HttpTransport),
        ("https://opamp.example.com/v1/opamp", HttpTransport),
        ("ws://127.0.0.1:4320/v1/opamp", WebSocketTransport),
        ("wss://opamp.example.com/v1/opamp", WebSocketTransport),
    ],
)
def test_transport_for_url_picks_by_scheme(url, expected):
    assert isinstance(transport_for_url(url), expected)


def test_transport_for_url_rejects_an_unknown_scheme():
    with pytest.raises(ValueError):
        transport_for_url("ftp://opamp.example.com/v1/opamp")


# -- the client's side of backoff -------------------------------------------


def test_client_never_retries_sooner_than_the_server_asked(monkeypatch):
    """Exponential backoff with jitter, floored by the server's own answer."""
    agent = type("A", (), {})()
    client = OpampClient(agent, lambda: None, retry_interval=0.2)

    assert client._next_delay(0.2, None) < 1.0
    assert client._next_delay(0.2, 30.0) >= 30.0
    # Jitter still applies, so a fleet shed together does not return together.
    assert len({client._next_delay(30.0, 30.0) for _ in range(20)}) > 1
