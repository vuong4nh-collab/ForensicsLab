"""
ForensicsLab Sandbox Manager — Layer 4
Manages Docker containers as isolated lab environments for each student.
"""
import docker
import logging
import threading
import time
import os
import shutil
from datetime import datetime, timedelta

EVIDENCE_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'evidence')

logger = logging.getLogger(__name__)


def _prepare_dynamic_s3_evidence(user_id: int) -> str:
    """Build a per-student temp directory with a patched memory_dump.vmem.

    Returns the absolute path to the temp directory so it can be mounted
    directly into the Docker container as /evidence/scenario_3.
    """
    # Import lazily to avoid circular imports at module load time
    from app import build_dynamic_vmem  # noqa: PLC0415

    temp_dir = os.path.join(EVIDENCE_BASE, f'temp_u{user_id}_s3')
    os.makedirs(temp_dir, exist_ok=True)

    # Write patched vmem
    vmem_path = os.path.join(temp_dir, 'memory_dump.vmem')
    data = build_dynamic_vmem(user_id)
    with open(vmem_path, 'wb') as f:
        f.write(data)

    # Copy static supporting files (readme, sha256 stub, etc.)
    static_s3 = os.path.join(EVIDENCE_BASE, 'scenario_3')
    for fname in os.listdir(static_s3):
        if fname == 'memory_dump.vmem':
            continue  # already written the patched version
        src = os.path.join(static_s3, fname)
        dst = os.path.join(temp_dir, fname)
        if os.path.isfile(src) and not os.path.exists(dst):
            shutil.copy2(src, dst)

    # Write a fresh sha256 file for the patched vmem
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    with open(os.path.join(temp_dir, 'memory_dump.vmem.sha256'), 'w') as hf:
        hf.write(f'{sha}  memory_dump.vmem\n')

    logger.info(f'[S3-Dynamic] Prepared evidence for user {user_id} at {temp_dir}')
    return temp_dir


def _cleanup_dynamic_s3_evidence(user_id: int):
    """Remove the per-student temp evidence directory."""
    temp_dir = os.path.join(EVIDENCE_BASE, f'temp_u{user_id}_s3')
    if os.path.isdir(temp_dir):
        try:
            shutil.rmtree(temp_dir)
            logger.info(f'[S3-Dynamic] Cleaned up temp evidence for user {user_id}')
        except Exception as e:
            logger.warning(f'[S3-Dynamic] Could not clean up {temp_dir}: {e}')

FORENSICS_IMAGE = "forensicslab:latest"
CONTAINER_PREFIX = "forensicslab_"
MAX_IDLE_MINUTES = 30
MAX_CONTAINERS = 10  # global limit
CONTAINER_MEMORY_LIMIT = "768m"
CONTAINER_CPU_LIMIT = 500_000_000  # 0.5 CPU
SANDBOX_REQUIRED_TOOLS = ["tshark", "fls", "icat", "ewfinfo", "strings", "xxd", "vol"]

_client = None
_lock = threading.Lock()


def get_docker_client():
    global _client
    if _client is None:
        try:
            _client = docker.from_env()
            _client.ping()
        except Exception as e:
            logger.error(f"Docker unavailable: {e}")
            _client = None
    return _client


def is_docker_available():
    return get_docker_client() is not None


def is_image_available():
    """Check if the forensics Docker image exists locally."""
    client = get_docker_client()
    if not client:
        return False
    try:
        client.images.get(FORENSICS_IMAGE)
        return True
    except docker.errors.ImageNotFound:
        return False


def container_name(user_id, scenario_id):
    return f"{CONTAINER_PREFIX}u{user_id}_s{scenario_id}"


def scenario_workdir(scenario_id):
    return f"/evidence/scenario_{int(scenario_id)}"


def get_sandbox_status(user_id, scenario_id):
    """
    Returns dict:
      mode: 'docker_live' | 'simulated' | 'stopped'
      status: 'running' | 'stopped' | 'error'
      container_id: str or None
      uptime_seconds: int
      image_ready: bool
    """
    client = get_docker_client()
    image_ready = is_image_available()

    if not client:
        return {"mode": "simulated", "status": "stopped", "container_id": None,
                "uptime_seconds": 0, "image_ready": False}

    name = container_name(user_id, scenario_id)
    try:
        container = client.containers.get(name)
        if container.status == "running":
            # Calculate uptime
            started_at = container.attrs.get("State", {}).get("StartedAt", "")
            uptime = 0
            if started_at:
                try:
                    # Docker returns ISO format with timezone
                    started_dt = datetime.fromisoformat(started_at[:19])
                    uptime = int((datetime.utcnow() - started_dt).total_seconds())
                except Exception:
                    uptime = 0
            return {
                "mode": "docker_live",
                "status": "running",
                "container_id": container.short_id,
                "uptime_seconds": max(0, uptime),
                "image_ready": image_ready
            }
        else:
            return {"mode": "simulated", "status": "stopped",
                    "container_id": container.short_id, "uptime_seconds": 0,
                    "image_ready": image_ready}
    except docker.errors.NotFound:
        return {"mode": "simulated", "status": "stopped", "container_id": None,
                "uptime_seconds": 0, "image_ready": image_ready}
    except Exception as e:
        logger.error(f"get_sandbox_status error: {e}")
        return {"mode": "simulated", "status": "error", "container_id": None,
                "uptime_seconds": 0, "image_ready": image_ready}


def start_sandbox(user_id, scenario_id):
    """
    Start (or restart) a Docker container for this user+scenario.
    Returns (success: bool, message: str, container_id: str|None)
    """
    client = get_docker_client()
    if not client:
        return False, "Docker không khả dụng trên máy chủ.", None

    if not is_image_available():
        return False, f"Image '{FORENSICS_IMAGE}' chưa được build. Vui lòng chạy: docker build -f Dockerfile.forensics -t {FORENSICS_IMAGE} .", None

    # Check global container count
    try:
        running = client.containers.list(filters={"name": CONTAINER_PREFIX})
        if len(running) >= MAX_CONTAINERS:
            return False, f"Hệ thống đã đạt giới hạn {MAX_CONTAINERS} sandbox đang chạy. Vui lòng thử lại sau.", None
    except Exception:
        pass

    name = container_name(user_id, scenario_id)

    # Remove existing stopped container
    try:
        old = client.containers.get(name)
        if old.status != "running":
            old.remove(force=True)
    except docker.errors.NotFound:
        pass
    except Exception as e:
        logger.warning(f"Could not remove old container: {e}")

    try:
        # For Scenario 3: create per-student patched vmem and mount only that dir
        if scenario_id == 3:
            try:
                s3_temp_dir = _prepare_dynamic_s3_evidence(user_id)
                # Mount the static evidence base (read-only) PLUS the dynamic s3 dir
                volumes_config = {
                    os.path.abspath(EVIDENCE_BASE): {
                        'bind': '/evidence',
                        'mode': 'ro'
                    },
                    os.path.abspath(s3_temp_dir): {
                        'bind': '/evidence/scenario_3',
                        'mode': 'ro'
                    }
                }
            except Exception as e:
                logger.warning(f'Dynamic S3 evidence prep failed, falling back to static: {e}')
                volumes_config = {
                    os.path.abspath(EVIDENCE_BASE): {'bind': '/evidence', 'mode': 'ro'}
                }
        else:
            volumes_config = {
                os.path.abspath(EVIDENCE_BASE): {'bind': '/evidence', 'mode': 'ro'}
            }

        container = client.containers.run(
            FORENSICS_IMAGE,
            name=name,
            detach=True,
            stdin_open=True,
            tty=True,
            mem_limit=CONTAINER_MEMORY_LIMIT,
            nano_cpus=CONTAINER_CPU_LIMIT,
            network_mode="none",    # fully isolated
            read_only=False,
            remove=False,
            working_dir=scenario_workdir(scenario_id),
            volumes=volumes_config,
            labels={
                "forensicslab": "1",
                "user_id": str(user_id),
                "scenario_id": str(scenario_id),
                "started_at": datetime.utcnow().isoformat()
            }
        )
        check_cmd = " && ".join(f"command -v {tool}" for tool in SANDBOX_REQUIRED_TOOLS)
        tool_check = container.exec_run(
            cmd=["bash", "-lc", check_cmd],
            workdir=scenario_workdir(scenario_id),
        )
        if tool_check.exit_code != 0:
            missing_cmd = (
                "for t in " + " ".join(SANDBOX_REQUIRED_TOOLS) +
                "; do command -v \"$t\" >/dev/null 2>&1 || echo \"$t\"; done"
            )
            missing = container.exec_run(
                cmd=["bash", "-lc", missing_cmd],
                workdir=scenario_workdir(scenario_id),
            )
            missing_output = missing.output.decode("utf-8", errors="replace").strip() if missing.output else "unknown"
            container.stop(timeout=3)
            container.remove(force=True)
            return False, f"Image sandbox thiếu công cụ bắt buộc: {missing_output}", None
        return True, "Sandbox đã khởi động thành công!", container.short_id
    except docker.errors.APIError as e:
        logger.error(f"start_sandbox APIError: {e}")
        return False, f"Lỗi Docker: {str(e)[:120]}", None
    except Exception as e:
        logger.error(f"start_sandbox error: {e}")
        return False, f"Lỗi không xác định: {str(e)[:100]}", None


def stop_sandbox(user_id, scenario_id):
    """Stop and remove a running container."""
    client = get_docker_client()
    if not client:
        return False, "Docker không khả dụng."
    name = container_name(user_id, scenario_id)
    try:
        container = client.containers.get(name)
        container.stop(timeout=5)
        container.remove(force=True)
        if scenario_id == 3:
            _cleanup_dynamic_s3_evidence(user_id)
        return True, "Sandbox đã dừng."
    except docker.errors.NotFound:
        if scenario_id == 3:
            _cleanup_dynamic_s3_evidence(user_id)
        return True, "Sandbox không tồn tại."
    except Exception as e:
        logger.error(f"stop_sandbox error: {e}")
        return False, f"Lỗi: {str(e)[:100]}"


def reset_sandbox(user_id, scenario_id):
    """Stop, remove, then restart the container."""
    stop_sandbox(user_id, scenario_id)
    return start_sandbox(user_id, scenario_id)



# ── Whitelist of allowed forensics binaries ────────────────────────────────
# Only these base commands are allowed in the Docker sandbox.
# This is safer than a blacklist — deny by default, allow explicitly.
ALLOWED_COMMANDS = {
    # Network forensics
    "tshark", "tcpdump", "capinfos", "editcap", "mergecap", "reordercap",
    # File system forensics
    "ls", "cat", "file", "find", "head", "tail", "wc", "stat", "du",
    "fls", "icat", "fsstat", "ffind", "istat",
    # Disk / image tools
    "ewfinfo", "ewfmount", "mmls", "mmstat", "blkid", "fdisk",
    # String / hex analysis
    "strings", "xxd", "hexdump", "od", "grep", "awk", "cut", "sort",
    "uniq", "tr", "sed",
    # Hash & integrity
    "md5sum", "sha1sum", "sha256sum", "sha512sum",
    # Volatility memory forensics
    "vol", "vol.py", "volatility", "volatility3",
    # Misc safe utils
    "echo", "pwd", "id", "uname", "date", "which", "env", "printenv",
    "diff", "cmp",
}

# Dangerous shell metacharacters — always blocked even in whitelisted cmds
_BLOCKED_CHARS = [">", ">>", "|", ";", "&&", "||", "`", "$(", "<"]


def _is_command_allowed(command: str) -> tuple[bool, str]:
    """
    Returns (allowed, reason).
    Checks metacharacter injection first, then verifies the base binary
    is in ALLOWED_COMMANDS.
    """
    for ch in _BLOCKED_CHARS:
        if ch in command:
            return False, f"Ký tự không được phép: '{ch}'"
    base = command.strip().split()[0].lower() if command.strip() else ""
    if base not in ALLOWED_COMMANDS:
        return False, (
            f"Lệnh '{base}' không được phép trong sandbox. "
            f"Chỉ các công cụ điều tra số được cấp phép: "
            f"tshark, fls, icat, strings, xxd, md5sum, sha256sum, v.v."
        )
    return True, ""


def exec_command(user_id, scenario_id, command):
    """
    Execute a whitelisted forensics command inside the running container.
    Returns (success: bool, output: str)
    """
    client = get_docker_client()
    if not client:
        return False, "Docker không khả dụng."

    name = container_name(user_id, scenario_id)
    try:
        container = client.containers.get(name)
        if container.status != "running":
            return False, "Container không đang chạy. Hãy nhấn 'Start Sandbox' trước."

        # Security: whitelist check
        allowed, reason = _is_command_allowed(command)
        if not allowed:
            return False, f"[BLOCKED] {reason}"

        result = container.exec_run(
            cmd=["bash", "-c", command],
            workdir=scenario_workdir(scenario_id),
            user="nobody",          # Drop root privilege inside container
            demux=False,
            stdin=False,
        )
        output = result.output.decode("utf-8", errors="replace") if result.output else ""
        if result.exit_code != 0 and not output:
            output = f"Command exited with status {result.exit_code}"
        if len(output) > 8000:
            output = output[:8000] + "\n... [Output bị cắt ngắn - quá 8 KB]"
        return result.exit_code == 0, output
    except docker.errors.NotFound:
        return False, "Container không tồn tại. Hãy Start sandbox trước."
    except Exception as e:
        logger.error(f"exec_command error: {e}")
        return False, f"Lỗi thực thi: {str(e)[:100]}"



def cleanup_idle_sandboxes():
    """Background thread: stop containers idle > MAX_IDLE_MINUTES."""
    client = get_docker_client()
    if not client:
        return
    try:
        containers = client.containers.list(filters={"label": "forensicslab=1"})
        cutoff = datetime.utcnow() - timedelta(minutes=MAX_IDLE_MINUTES)
        for c in containers:
            started_at_str = c.labels.get("started_at", "")
            if started_at_str:
                try:
                    started_at = datetime.fromisoformat(started_at_str)
                    if started_at < cutoff:
                        logger.info(f"Auto-stopping idle container: {c.name}")
                        c.stop(timeout=3)
                        c.remove(force=True)
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"cleanup_idle_sandboxes error: {e}")


def start_cleanup_scheduler():
    """Start background cleanup thread (call once at app startup)."""
    def _run():
        while True:
            time.sleep(300)  # every 5 minutes
            try:
                cleanup_idle_sandboxes()
            except Exception:
                pass
    t = threading.Thread(target=_run, daemon=True)
    t.start()
