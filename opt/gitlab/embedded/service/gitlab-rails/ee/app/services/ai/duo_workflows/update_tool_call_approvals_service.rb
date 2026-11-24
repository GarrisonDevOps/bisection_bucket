# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class UpdateToolCallApprovalsService
      def initialize(workflow:, tool_name:, current_user:, tool_call_args: nil, pattern: nil, approval_source: nil)
        @workflow = workflow
        @tool_name = tool_name
        @tool_call_args = tool_call_args
        @pattern = pattern
        @approval_source = approval_source
        @current_user = current_user
      end

      def execute
        unless @tool_call_args.nil? ^ @pattern.nil?
          return error_response("Exactly one of tool_call_args or pattern must be provided")
        end

        unless Ability.allowed?(@current_user, :update_duo_workflow, @workflow)
          return error_response("Can not update workflow", :unauthorized)
        end

        unless tool_approval_for_session_enabled?
          return error_response("Tool approval for session is not enabled for this namespace", :forbidden)
        end

        if ::Ai::DuoWorkflows::ToolsRequiringAdminApprovalService.new(workflow: @workflow).execute.include?(@tool_name)
          return error_response("An administrator rule does not allow approving this tool for the session", :forbidden)
        end

        update_tool_call_approvals
      end

      private

      def update_tool_call_approvals
        # with_lock reloads the record before yielding, ensuring we read
        # the latest tool_call_approvals and prevent read-modify-write races.
        @workflow.with_lock('FOR UPDATE NOWAIT') do
          if @pattern
            @workflow.add_tool_call_pattern_approval(tool_name: @tool_name, pattern: @pattern)
          else
            @workflow.add_tool_call_approval(tool_name: @tool_name, call_args: @tool_call_args)
          end

          @workflow.save
        end

        if @workflow.errors.any?
          error_response("Failed to update tool_call_approvals: #{@workflow.errors.full_messages.join(', ')}")
        else
          audit_tool_call_approval
          ServiceResponse.success(
            payload: { workflow: @workflow },
            message: "Tool call approvals updated successfully"
          )
        end
      rescue ArgumentError => e
        error_response(e.message)
      rescue ActiveRecord::LockWaitTimeout
        error_response("Workflow is currently being updated, please try again")
      end

      def tool_approval_for_session_enabled?
        project = @workflow.project
        return project.project_setting.tool_approval_for_session_enabled? if project

        namespace = @workflow.namespace
        namespace&.namespace_settings&.tool_approval_for_session_enabled?
      end

      def audit_tool_call_approval
        scope = @workflow.project || @workflow.namespace

        message = if @pattern
                    "Approved tool call: #{@tool_name} with pattern: #{@pattern}"
                  else
                    "Approved tool call: #{@tool_name}"
                  end

        audit_context = {
          name: 'duo_tool_call_approved',
          author: @current_user,
          scope: scope,
          target: @workflow,
          target_details: "#{@workflow.workflow_definition} session #{@workflow.id}",
          message: message,
          additional_details: { approval_source: @approval_source, approval_scope: 'session' }.compact
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: @workflow.id)
      end

      def error_response(message, reason = :bad_request)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
