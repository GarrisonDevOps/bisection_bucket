#!/bin/sh

# Define log file path
LOG_FILE="${GL_WORKSPACE_LOGS_DIR}/start-agentw.log"

echo "$(date -Iseconds): ----------------------------------------"
echo "$(date -Iseconds): Starting Agent for Workspace(agentw) in background with output written to ${LOG_FILE}..."

mkdir -p "$(dirname "${LOG_FILE}")"

echo "$(date -Iseconds): Agentw initialization started"

# Start logging
exec 1>>"${LOG_FILE}" 2>&1

# This script starts Agent for Workspace(agentw).
#
# It uses the following environment variables
# $GL_TOOLS_DIR - directory where the tools are copied.
# $GL_GITLAB_AGENT_SERVER_ADDRESS - GitLab Agent Server(KAS) address used by Agent for Workspace(agentw) to connect to.
# $GL_AGENTW_TOKEN_FILE_PATH - the workspace token used by Agent for Workspace(agentw) to connect to GitLab Agent Server(KAS).
# $GL_AGENTW_OBSERVABILITY_LISTEN_ADDRESS - Observability listen address used by Agent for Workspace(agentw).

if [ -z "${GL_TOOLS_DIR}" ]; then
  echo "$(date -Iseconds): \$GL_TOOLS_DIR is not set"
  exit 1
fi

if [ -z "${GL_GITLAB_AGENT_SERVER_ADDRESS}" ]; then
  echo "$(date -Iseconds): \$GL_GITLAB_AGENT_SERVER_ADDRESS is not set"
  exit 1
fi

if [ -z "${GL_AGENTW_TOKEN_FILE_PATH}" ]; then
  echo "$(date -Iseconds): \$GL_AGENTW_TOKEN_FILE_PATH is not set"
  exit 1
fi

if [ -z "${GL_AGENTW_OBSERVABILITY_LISTEN_ADDRESS}" ]; then
  echo "$(date -Iseconds): \$GL_AGENTW_OBSERVABILITY_LISTEN_ADDRESS is not set"
  exit 1
fi

echo "$(date -Iseconds): Starting Agent for Workspace(agentw):"
echo "$(date -Iseconds): - GitLab Agent Server(KAS) address: ${GL_GITLAB_AGENT_SERVER_ADDRESS}"
echo "$(date -Iseconds): - Token file: ${GL_AGENTW_TOKEN_FILE_PATH}"
echo "$(date -Iseconds): - Observability listen address: ${GL_AGENTW_OBSERVABILITY_LISTEN_ADDRESS}"

# The server execution is backgrounded to allow for the rest of the internal init scripts to execute.
"${GL_TOOLS_DIR}/agentw" \
  --kas-address "${GL_GITLAB_AGENT_SERVER_ADDRESS}" \
  --token-file "${GL_AGENTW_TOKEN_FILE_PATH}" \
  --observability-listen-address "${GL_AGENTW_OBSERVABILITY_LISTEN_ADDRESS}" &

echo "$(date -Iseconds): Finished starting Agent for Workspace(agentw) in background"
echo "$(date -Iseconds): ----------------------------------------"
