# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Otel
      class CreateWorkflowService
        include ::Gitlab::Utils::StrongMemoize

        WORKFLOW_DEFINITION = 'developer/v1'
        MISSING_ITEM_CONSUMER_ERROR = 'Could not find enabled developer flow for this project'
        MISSING_SERVICE_ACCOUNT_ERROR = 'Could not resolve the service account for this flow'

        def initialize(project:, current_user:)
          @project = project
          @current_user = current_user
        end

        def execute
          return error(MISSING_ITEM_CONSUMER_ERROR) unless item_consumer
          return error(MISSING_SERVICE_ACCOUNT_ERROR) if service_account.nil?

          issue_result = create_issue
          return issue_result if issue_result.error?

          issue = issue_result.payload[:issue]

          workflow_result = execute_flow(issue)

          unless workflow_result.success?
            close_issue(issue)
            return workflow_result
          end

          workflow = workflow_result.payload[:workflow]

          begin
            associate_issue(workflow, issue)
          rescue StandardError => e
            ::Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
            close_issue(issue)
            return error('Failed to associate issue with workflow')
          end

          ServiceResponse.success(
            payload: {
              issue: issue,
              workflow: workflow,
              workload_id: workflow_result.payload[:workload_id]
            }
          )
        end

        private

        attr_reader :project, :current_user

        def execute_flow(issue)
          goal = ::Gitlab::UrlBuilder.build(issue)

          ::Ai::Catalog::Flows::ExecuteService.new(
            project: project,
            current_user: current_user,
            params: {
              item_consumer: item_consumer,
              service_account: service_account,
              execute_workflow: true,
              event_type: 'otel_execution',
              user_prompt: goal,
              source_branch: project.default_branch
            }
          ).execute
        end

        def associate_issue(workflow, issue)
          workflow.update!(issue: issue)
          SystemNoteService.agent_session_started(issue, project, workflow.id, current_user, service_account)
        end

        def create_issue
          ::Issues::CreateService.new(
            container: project,
            current_user: current_user,
            params: {
              title: ::Gitlab::Duo::Otel::GoalTemplates.issue_title,
              description: ::Gitlab::Duo::Otel::GoalTemplates.build_description(primary_language)
            },
            perform_spam_check: false
          ).execute
        end

        def close_issue(issue)
          ::Issues::CloseService.new(
            container: project,
            current_user: current_user
          ).execute(issue)
        end

        def item_consumer
          ::Ai::Catalog::ItemConsumersFinder.new(current_user, params: {
            project_id: project.id,
            item_type: Ai::Catalog::Item::FLOW_TYPE,
            foundational_flow_reference: WORKFLOW_DEFINITION,
            include_inherited: false
          }).execute.first
        end
        strong_memoize_attr :item_consumer

        def service_account
          if item_consumer.project.present?
            item_consumer.parent_item_consumer&.service_account
          else
            item_consumer.service_account
          end
        end
        strong_memoize_attr :service_account

        def primary_language
          project.repository_languages.first&.name
        end
        strong_memoize_attr :primary_language

        def error(message, reason: nil)
          ServiceResponse.error(message: message, reason: reason)
        end
      end
    end
  end
end
