#!/usr/bin/env bash
# Start, check, or stop the local llama-server sidecar for AGY Guardian (Git Bash / POSIX).
#
# Settings precedence: CLI flags > OS env vars > .env > defaults.
# Shares .local/llama-server.pid and .local/llama-server.log with start_llama_server.ps1.
#
# Usage:
#   ./scripts/start_llama_server.sh [start|--background|-d]
#   ./scripts/start_llama_server.sh --foreground | -f
#   ./scripts/start_llama_server.sh status | --status
#   ./scripts/start_llama_server.sh stop   | --stop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCAL_DIR="$REPO_ROOT/.local"
PID_FILE="$LOCAL_DIR/llama-server.pid"
LOG_FILE="$LOCAL_DIR/llama-server.log"
ERR_LOG_FILE="$LOCAL_DIR/llama-server.err.log"
ENV_FILE="$REPO_ROOT/.env"

ACTION="start"
FOREGROUND=0
CLI_BACKEND=""
CLI_MODEL=""
CLI_SERVER=""
CLI_HOST=""
CLI_PORT=""
CLI_NGL=""
WAIT_SECONDS=60

usage() {
    cat <<'EOF'
Usage: start_llama_server.sh [start|status|stop] [options]

Options:
  -d, --background           Start llama-server detached in background (default)
  -f, --foreground           Run llama-server attached in foreground
      --status               Check /health and PID status
      --stop                 Stop tracked llama-server process
      --backend MODE         systemone (default) or completion
      --model PATH           Override GGUF model path
      --llama-server PATH    Override llama-server executable path
      --host HOST            Bind host (default: 127.0.0.1)
      --port PORT            Bind port (default: 8099)
      --ngl N                GPU layers to offload (default: 99)
      --wait SECONDS         Health check wait timeout (default: 60)
  -h, --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        start)
            ACTION="start"
            shift
            ;;
        status|--status)
            ACTION="status"
            shift
            ;;
        stop|--stop)
            ACTION="stop"
            shift
            ;;
        -d|--background)
            FOREGROUND=0
            shift
            ;;
        -f|--foreground)
            FOREGROUND=1
            shift
            ;;
        --backend)
            CLI_BACKEND="${2:?Missing value for --backend}"
            shift 2
            ;;
        --model)
            CLI_MODEL="${2:?Missing value for --model}"
            shift 2
            ;;
        --llama-server)
            CLI_SERVER="${2:?Missing value for --llama-server}"
            shift 2
            ;;
        --host)
            CLI_HOST="${2:?Missing value for --host}"
            shift 2
            ;;
        --port)
            CLI_PORT="${2:?Missing value for --port}"
            shift 2
            ;;
        --ngl)
            CLI_NGL="${2:?Missing value for --ngl}"
            shift 2
            ;;
        --wait)
            WAIT_SECONDS="${2:?Missing value for --wait}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

IS_WINDOWS=0
case "$(uname -s 2>/dev/null || echo "")" in
    MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

# Load .env into an associative array without clobbering existing OS env vars
declare -A DOTENV=()
if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        line="${raw_line%$'\r'}"
        # Strip UTF-8 BOM on first line if present
        line="${line#$'\xef\xbb\xbf'}"
        # Trim leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == \#* || "$line" != *=* ]] && continue
        if [[ "$line" == export\ * ]]; then
            line="${line#export }"
            line="${line#"${line%%[![:space:]]*}"}"
        fi
        key="${line%%=*}"
        val="${line#*=}"
        key="${key%"${key##*[![:space:]]}"}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%"${val##*[![:space:]]}"}"
        if [[ ${#val} -ge 2 ]]; then
            if [[ ( "$val" == \"*\" ) || ( "$val" == \'*\' ) ]]; then
                val="${val:1:${#val}-2}"
            fi
        fi
        if [[ -n "$key" ]]; then
            DOTENV["$key"]="$val"
        fi
    done < "$ENV_FILE"
fi

get_setting() {
    local cli_val="$1"
    local env_key="$2"
    local default_val="${3:-}"
    if [[ -n "$cli_val" ]]; then
        printf '%s' "$cli_val"
        return
    fi
    local os_val="${!env_key:-}"
    if [[ -n "$os_val" ]]; then
        printf '%s' "$os_val"
        return
    fi
    if [[ -n "${DOTENV[$env_key]+x}" && -n "${DOTENV[$env_key]}" ]]; then
        printf '%s' "${DOTENV[$env_key]}"
        return
    fi
    printf '%s' "$default_val"
}

expand_template_path() {
    local raw="$1"
    [[ -z "$raw" ]] && return
    # Expand ${VAR} placeholders from OS env or .env
    while [[ "$raw" =~ \$\{([A-Za-z_][A-Za-z0-9_]*)\} ]]; do
        local var_name="${BASH_REMATCH[1]}"
        local repl="${!var_name:-}"
        if [[ -z "$repl" && -n "${DOTENV[$var_name]+x}" ]]; then
            repl="${DOTENV[$var_name]}"
        fi
        [[ -z "$repl" ]] && break
        raw="${raw//\$\{$var_name\}/$repl}"
    done
    # Expand leading ~
    if [[ "$raw" == "~" ]]; then
        raw="$HOME"
    elif [[ "$raw" == "~/"* || "$raw" == "~\\"* ]]; then
        raw="$HOME/${raw:2}"
    fi
    printf '%s' "$raw"
}

to_unix_path() {
    local p="$1"
    if [[ "$IS_WINDOWS" -eq 1 ]] && command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$p"
    else
        printf '%s' "$p"
    fi
}

to_native_path() {
    local p="$1"
    if [[ "$IS_WINDOWS" -eq 1 ]] && command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$p"
    else
        printf '%s' "$p"
    fi
}

test_health() {
    local endpoint="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 2 "$endpoint/health" >/dev/null 2>&1
        return $?
    fi
    python -c "import sys, urllib.request; urllib.request.urlopen('$endpoint/health', timeout=2)" >/dev/null 2>&1
}

pid_is_running() {
    local pid="$1"
    [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]] && return 1
    if [[ "$IS_WINDOWS" -eq 1 ]]; then
        # Check exact Windows PID via CSV tasklist (works across Git Bash windows & PowerShell)
        local out
        out="$(MSYS_NO_PATHCONV=1 tasklist.exe /FI "PID eq $pid" /FO CSV /NH 2>/dev/null || true)"
        [[ "$out" == *"\"$pid\""* ]]
        return $?
    fi
    kill -0 "$pid" 2>/dev/null
}

kill_saved_pid() {
    local pid="$1"
    if [[ "$IS_WINDOWS" -eq 1 ]]; then
        MSYS_NO_PATHCONV=1 taskkill.exe /F /PID "$pid" >/dev/null 2>&1
    else
        kill "$pid" 2>/dev/null
    fi
}

EFFECTIVE_HOST="$(get_setting "$CLI_HOST" "AGY_GUARDIAN_HOST" "127.0.0.1")"
EFFECTIVE_PORT="$(get_setting "$CLI_PORT" "AGY_GUARDIAN_PORT" "8099")"
ENDPOINT="http://${EFFECTIVE_HOST}:${EFFECTIVE_PORT}"

if [[ "$ACTION" == "status" ]]; then
    pid_info="none"
    if [[ -f "$PID_FILE" ]]; then
        saved_pid="$(tr -d '\r\n ' < "$PID_FILE" 2>/dev/null || true)"
        if [[ -n "$saved_pid" ]]; then
            if pid_is_running "$saved_pid"; then
                pid_info="PID $saved_pid (running)"
            else
                pid_info="PID $saved_pid (stale)"
            fi
        fi
    fi
    if test_health "$ENDPOINT"; then
        echo "[OK] llama-server is healthy at $ENDPOINT ($pid_info)"
        exit 0
    else
        echo "[DOWN] llama-server is not responding at $ENDPOINT ($pid_info)"
        exit 1
    fi
fi

if [[ "$ACTION" == "stop" ]]; then
    if [[ ! -f "$PID_FILE" ]]; then
        echo "No PID file found at $PID_FILE."
        exit 0
    fi
    saved_pid="$(tr -d '\r\n ' < "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$saved_pid" ]]; then
        if pid_is_running "$saved_pid"; then
            kill_saved_pid "$saved_pid"
            echo "Stopped llama-server (PID $saved_pid)."
        else
            echo "Process $saved_pid is not running."
        fi
    fi
    rm -f "$PID_FILE"
    exit 0
fi

# Idempotency check before starting
if test_health "$ENDPOINT"; then
    echo "[OK] llama-server is already running and healthy at $ENDPOINT."
    exit 0
fi

EFFECTIVE_BACKEND="$(get_setting "$CLI_BACKEND" "AGY_GUARDIAN_BACKEND" "systemone")"
[[ "$EFFECTIVE_BACKEND" == "auto" ]] && EFFECTIVE_BACKEND="systemone"
if [[ "$EFFECTIVE_BACKEND" != "systemone" && "$EFFECTIVE_BACKEND" != "completion" ]]; then
    echo "ERROR: Unsupported backend '$EFFECTIVE_BACKEND' (expected systemone or completion)." >&2
    exit 2
fi

RAW_SERVER="$(get_setting "$CLI_SERVER" "AGY_GUARDIAN_LLAMA_SERVER" "")"
if [[ -n "$RAW_SERVER" ]]; then
    SERVER_EXE_UNIX="$(to_unix_path "$(expand_template_path "$RAW_SERVER")")"
else
    SERVER_EXE_UNIX="$(command -v llama-server 2>/dev/null || true)"
fi
if [[ -z "$SERVER_EXE_UNIX" || ! -f "$SERVER_EXE_UNIX" ]]; then
    echo "ERROR: Could not locate llama-server. Set AGY_GUARDIAN_LLAMA_SERVER in .env or add llama-server to PATH." >&2
    exit 2
fi

DEFAULT_MODEL_TEMPLATE='${AGY_GUARDIAN_DECISION_MODELS_DIR}/Cloudflare_clef-flash-Q5_K_M.gguf'
RAW_MODEL="$(get_setting "$CLI_MODEL" "AGY_GUARDIAN_MODEL_PATH" "$DEFAULT_MODEL_TEMPLATE")"
EXPANDED_MODEL="$(expand_template_path "$RAW_MODEL")"
MODEL_UNIX="$(to_unix_path "$EXPANDED_MODEL")"
if [[ -z "$MODEL_UNIX" || ! -f "$MODEL_UNIX" ]]; then
    echo "ERROR: Model file not found: $EXPANDED_MODEL. Configure AGY_GUARDIAN_MODEL_PATH or AGY_GUARDIAN_DECISION_MODELS_DIR in .env." >&2
    exit 2
fi
MODEL_ARG="$(to_native_path "$MODEL_UNIX")"

EFFECTIVE_NGL="$(get_setting "$CLI_NGL" "AGY_GUARDIAN_GPU_LAYERS" "99")"

ARGS=(
    -m "$MODEL_ARG"
    --host "$EFFECTIVE_HOST"
    --port "$EFFECTIVE_PORT"
    -ngl "$EFFECTIVE_NGL"
    --ctx-size 2048
    -np 1
)
if [[ "$EFFECTIVE_BACKEND" == "systemone" ]]; then
    # Decision Models run in embedding mode: n_batch and n_ubatch must match ctx-size to avoid HTTP 500
    ARGS+=(-b 2048 -ub 2048)
fi

mkdir -p "$LOCAL_DIR"

if [[ "$FOREGROUND" -eq 1 ]]; then
    echo "Starting llama-server in foreground at $ENDPOINT (backend=$EFFECTIVE_BACKEND)..."
    exec env MSYS_NO_PATHCONV=1 "$SERVER_EXE_UNIX" "${ARGS[@]}"
fi

echo "Starting llama-server in background at $ENDPOINT (backend=$EFFECTIVE_BACKEND)..."
if [[ "$IS_WINDOWS" -eq 1 ]]; then
    SERVER_EXE_NATIVE="$(to_native_path "$SERVER_EXE_UNIX")"
    LOG_FILE_NATIVE="$(to_native_path "$LOG_FILE")"
    ERR_LOG_NATIVE="$(to_native_path "$ERR_LOG_FILE")"
    RECORD_PID="$(MSYS_NO_PATHCONV=1 python -c '
import subprocess, sys
log_out, log_err, exe = sys.argv[1], sys.argv[2], sys.argv[3]
args = [exe] + sys.argv[4:]
flags = (
    getattr(subprocess, "DETACHED_PROCESS", 0)
    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
)
with open(log_out, "wb") as fo, open(log_err, "wb") as fe:
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=fo,
        stderr=fe,
        creationflags=flags,
        close_fds=True,
    )
print(proc.pid)
' "$LOG_FILE_NATIVE" "$ERR_LOG_NATIVE" "$SERVER_EXE_NATIVE" "${ARGS[@]}")"
    RECORD_PID="${RECORD_PID%$'\r'}"
else
    nohup "$SERVER_EXE_UNIX" "${ARGS[@]}" >"$LOG_FILE" 2>"$ERR_LOG_FILE" </dev/null &
    RECORD_PID=$!
    disown "$RECORD_PID" 2>/dev/null || true
fi
printf '%s\n' "$RECORD_PID" > "$PID_FILE"

DEADLINE=$((SECONDS + WAIT_SECONDS))
while (( SECONDS < DEADLINE )); do
    if ! pid_is_running "$RECORD_PID"; then
        echo "ERROR: llama-server exited prematurely. Check $LOG_FILE and $ERR_LOG_FILE." >&2
        rm -f "$PID_FILE"
        exit 1
    fi
    if test_health "$ENDPOINT"; then
        echo "[OK] llama-server ready at $ENDPOINT (PID $RECORD_PID, logs: $LOG_FILE)"
        exit 0
    fi
    sleep 0.5
done

echo "ERROR: Timed out waiting for $ENDPOINT/health after ${WAIT_SECONDS}s (PID $RECORD_PID). Check $LOG_FILE and $ERR_LOG_FILE." >&2
exit 1
