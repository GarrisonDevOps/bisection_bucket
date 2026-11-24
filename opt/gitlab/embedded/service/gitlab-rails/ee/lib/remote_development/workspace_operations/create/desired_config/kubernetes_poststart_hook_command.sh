#!/bin/sh

component_name="%<component_name>s"
main_component_name="%<main_component_name>s"

mkdir -p "${GL_WORKSPACE_LOGS_DIR}/${component_name}"
ln -sf "${GL_WORKSPACE_LOGS_DIR}" /tmp

{
  echo "$(date -Iseconds): ----------------------------------------"
  echo "$(date -Iseconds): Running poststart commands for workspace..."
}>> "${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stdout.log"


if [ "${component_name}" = "${main_component_name}" ]; then
  {
    echo "$(date -Iseconds): ----------------------------------------"
    echo "$(date -Iseconds): Running internal blocking poststart commands script..."
  } >> "${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stdout.log"

  "%<run_internal_blocking_poststart_commands_script_file_path>s" 1>>"${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stdout.log" 2>>"${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stderr.log"
fi

{
  echo "$(date -Iseconds): ----------------------------------------"
  echo "$(date -Iseconds): Running non-blocking poststart commands script..."
} >> "${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stdout.log"

"%<run_non_blocking_poststart_commands_script_file_path>s" 1>>"${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stdout.log" 2>>"${GL_WORKSPACE_LOGS_DIR}/${component_name}/poststart-stderr.log" &
