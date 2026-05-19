"""
Smoke Test
==========

A minimal smoke test to ensure nsproxy binary can start and execute
a simple command in direct mode (-D).

Tests:
------
test_000smoke
    Run 'nsproxy -D true' and verify it exits with code 0.

Usage:
------
    pytest -v tests/test_000smoke.py
"""

from .conftest import managed_proc


def test_000smoke(nsproxy_runner):
    """Run nsproxy -D true and verify it exits with code 0"""
    with managed_proc(nsproxy_runner(["-D", "true"])) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )


def test_quiet_does_not_consume_command(nsproxy_runner):
    """Run nsproxy -q true and verify -q does not consume the command name."""
    with managed_proc(nsproxy_runner(["-q", "true"])) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert "missing argument" not in cl_out
    assert "missing argument" not in cl_err


def test_log_file_option(nsproxy_runner, tmp_path):
    """Run nsproxy with -l and verify logs are written to the requested file."""
    log_file = tmp_path / "nsproxy.log"

    with managed_proc(nsproxy_runner(["-l", str(log_file), "-D", "true"])) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert "[nsproxy]" not in cl_err
    assert "Log File:" in log_file.read_text()


def test_quiet_with_log_file_still_writes_log(nsproxy_runner, tmp_path):
    """Run nsproxy with -q -l and verify quiet does not suppress file logs."""
    log_file = tmp_path / "nsproxy-quiet.log"

    with managed_proc(
        nsproxy_runner(["-q", "-l", str(log_file), "-D", "true"])
    ) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert "[nsproxy]" not in cl_err
    assert "Log File:" in log_file.read_text()


def test_verbose_does_not_write_stdout(nsproxy_runner):
    """Run nsproxy with -v and verify nsproxy logs stay off stdout."""
    with managed_proc(nsproxy_runner(["-v", "-D", "true"])) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert cl_out == ""
    assert "[nsproxy]" in cl_err


def test_verbose_with_log_file_does_not_write_stdio(nsproxy_runner, tmp_path):
    """Run nsproxy with -v -l and verify verbose logs only go to the log file."""
    log_file = tmp_path / "nsproxy-verbose.log"

    with managed_proc(
        nsproxy_runner(["-v", "-l", str(log_file), "-D", "true"])
    ) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")
    log_text = log_file.read_text()

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert "[nsproxy]" not in cl_out
    assert "[nsproxy]" not in cl_err
    assert "Verbose:          yes" in log_text
    assert "Child process" in log_text


def test_quiet_log_file_then_verbose_writes_verbose_log(nsproxy_runner, tmp_path):
    """Run nsproxy with -q -l ... -v and verify -v still affects file logs."""
    log_file = tmp_path / "nsproxy-quiet-verbose.log"

    with managed_proc(
        nsproxy_runner(["-q", "-l", str(log_file), "-N", "-v", "-D", "true"])
    ) as client:
        cl_stdout, cl_stderr = client.communicate(timeout=3)

    cl_out = cl_stdout.decode(errors="replace")
    cl_err = cl_stderr.decode(errors="replace")
    log_text = log_file.read_text()

    assert client.returncode == 0, (
        f"Client exited with error code {client.returncode}. "
        f"stdout: {cl_out}, stderr: {cl_err}"
    )
    assert "[nsproxy]" not in cl_out
    assert "[nsproxy]" not in cl_err
    assert "Proxy half-close forwarding: disabled (-N)" in log_text
    assert "Verbose:          yes" in log_text
    assert "Child process" in log_text
