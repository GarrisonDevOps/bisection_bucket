# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowSourceTypeEnum < BaseEnum
        graphql_name 'DuoWorkflowSourceType'
        description 'Where a Duo Workflow session was initiated from.'

        # Descriptions are spelled out rather than derived from Workflow.source_types
        # because no single transformation renders both `Slack` and `MCP` correctly.
        value 'SLACK', value: 'slack', description: 'Session initiated from Slack.'
        value 'MCP', value: 'mcp', description: 'Session initiated from MCP.'
        value 'MERGE_REQUEST_CODE_CONFLICT', value: 'merge_request_code_conflict',
          description: 'Session initiated from resolving a merge request conflict.'
        value 'MERGE_REQUEST_DEPENDENCY_BUMP', value: 'merge_request_dependency_bump',
          description: 'Session initiated from bumping a dependency on a merge request.'
        value 'MERGE_REQUEST_FIX_PIPELINE', value: 'merge_request_fix_pipeline',
          description: 'Session initiated from fixing a failed pipeline on a merge request.'
        value 'MERGE_REQUEST_RESOLVE_DISCUSSION', value: 'merge_request_resolve_discussion',
          description: 'Session initiated from resolving a discussion on a merge request.'
        value 'WORK_ITEM_TO_MERGE_REQUEST', value: 'work_item_to_merge_request',
          description: 'Session initiated from creating a merge request from a work item.'
        value 'FIX_PIPELINE', value: 'fix_pipeline',
          description: 'Session initiated from fixing a failed pipeline.'
        value 'CONVERT_PLATFORM_CI_PIPELINE', value: 'convert_platform_ci_pipeline',
          description: 'Session initiated from converting a CI pipeline to GitLab CI.'
        value 'DUO_CLI_INTERACTIVE', value: 'duo_cli_interactive',
          description: 'Session initiated from GitLab Duo CLI in interactive mode.'
        value 'DUO_CLI_RUN', value: 'duo_cli_run',
          description: 'Session initiated from GitLab Duo CLI in run mode.'
        value 'DUO_CLI_ACP', value: 'duo_cli_acp',
          description: 'Session initiated from GitLab Duo CLI over ACP.'
        value 'IDE_EXTENSION', value: 'ide_extension',
          description: 'Session initiated from an IDE extension.'
        value 'FLOW_TRIGGER', value: 'flow_trigger',
          description: 'Session initiated by a flow trigger.'
        value 'WORK_ITEM_PLAN_TO_MERGE_REQUEST', value: 'work_item_plan_to_merge_request',
          description: 'Session initiated from creating a merge request from an existing workplan for a work item.'
        value 'WEB_CHAT', value: 'web_chat',
          description: 'Session initiated from GitLab Duo Chat in the web UI.'
        value 'WORK_ITEM_WORKPLAN', value: 'work_item_workplan',
          description: 'Session initiated from generating a workplan for a work item.'
        value 'VULNERABILITY_LEAKED_TOKEN_ROTATION', value: 'vulnerability_leaked_token_rotation',
          description: 'Session initiated from rotating a leaked token found by a vulnerability.'
        value 'MOBILE_CHAT', value: 'mobile_chat',
          description: 'Session initiated from GitLab Duo Chat in the GitLab Mobile app.'
      end
    end
  end
end
