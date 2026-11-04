"""Platform dispatch: the same Thrift IDL over two different transports.

osquery's extension API is a Unix domain socket on POSIX and a named pipe on
Windows. The *path arithmetic* is identical on both (``getExtensionSocket()``
is string concatenation), and that shared half is tested here. The Windows
transport itself is exercised in ``test_winpipe.py``.
"""

from __future__ import annotations

import os

import pytest

from osquery_opamp import osquery_thrift


def test_default_manager_socket_is_the_unix_path_off_windows(monkeypatch):
    monkeypatch.delenv("OSQUERY_EXTENSIONS_SOCKET", raising=False)
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: False)
    assert osquery_thrift.default_manager_socket() == "/var/osquery/osquery.em"


def test_default_manager_socket_is_a_named_pipe_on_windows(monkeypatch):
    """Mirrors OSQUERY_SOCKET "osquery.em" in default_paths.h."""
    monkeypatch.delenv("OSQUERY_EXTENSIONS_SOCKET", raising=False)
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: True)
    assert osquery_thrift.default_manager_socket() == r"\\.\pipe\osquery.em"


def test_env_override_wins_on_both_platforms(monkeypatch):
    monkeypatch.setenv("OSQUERY_EXTENSIONS_SOCKET", r"\\.\pipe\custom.em")
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: True)
    assert osquery_thrift.default_manager_socket() == r"\\.\pipe\custom.em"
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: False)
    assert osquery_thrift.default_manager_socket() == r"\\.\pipe\custom.em"


@pytest.mark.parametrize(
    "manager,uuid,expected",
    [
        ("/var/osquery/osquery.em", 0, "/var/osquery/osquery.em"),
        ("/var/osquery/osquery.em", 7, "/var/osquery/osquery.em.7"),
        (r"\\.\pipe\osquery.em", 4242, r"\\.\pipe\osquery.em.4242"),
    ],
)
def test_extension_socket_path_matches_get_extension_socket(manager, uuid, expected):
    """``(uuid == 0) ? path : path + "." + uuid``, on every platform."""
    assert osquery_thrift.extension_socket_path(manager, uuid) == expected


def test_is_windows_is_false_on_this_runner():
    assert osquery_thrift.is_windows() is False


def test_close_extension_socket_is_a_noop_on_windows(monkeypatch):
    """Named pipes vanish with their last handle; there is nothing to unlink."""
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: True)
    osquery_thrift.close_extension_socket(r"\\.\pipe\osquery.em.1")


def test_close_extension_socket_removes_the_path_off_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: False)
    path = tmp_path / "osq.em.1"
    path.write_text("")
    osquery_thrift.close_extension_socket(str(path))
    assert not os.path.exists(path)


def test_close_extension_socket_tolerates_a_missing_path(tmp_path, monkeypatch):
    monkeypatch.setattr(osquery_thrift, "is_windows", lambda: False)
    osquery_thrift.close_extension_socket(str(tmp_path / "gone"))


def test_poke_extension_socket_swallows_a_missing_socket(tmp_path):
    """stop() pokes unconditionally; a dead daemon must not raise."""
    osquery_thrift.poke_extension_socket(str(tmp_path / "gone"))
