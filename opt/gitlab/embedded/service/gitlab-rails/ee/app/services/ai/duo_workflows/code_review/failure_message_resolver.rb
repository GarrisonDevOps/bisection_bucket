# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class FailureMessageResolver
        KNOWN_FAILURE_MESSAGES = {
          flow_not_enabled: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.foundational_flow_not_enabled_error
          },
          invalid_service_account: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.missing_service_account_error
          },
          service_account_error: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.missing_service_account_error
          },
          usage_quota_exceeded: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.usage_quota_exceeded_error
          },
          usage_billing_forbidden: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.usage_billing_forbidden_error
          },
          namespace_missing: ->(user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.namespace_missing_error(user)
          },
          cannot_create_workflow_pipeline: ->(user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.insufficient_workload_permissions_error(user)
          },
          workload_failure: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.workload_creation_error
          },
          workflow_workload_failure: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.workload_creation_error
          },
          feature_unavailable: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.feature_unavailable_error
          },
          invalid_duo_workflow_token: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.invalid_token_error
          },
          invalid_oauth_token: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.invalid_token_error
          },
          source_ref_not_found: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.source_ref_not_found_error
          },
          no_eligible_runner: ->(_user, project) {
            ::Gitlab::Duo::CodeReview::Messages.no_eligible_runner_error(
              tag: ::Ai::DuoWorkflows::Workflow.workload_tag_for(project)
            )
          },
          namespace_ci_minutes_used_up: ->(_user, _project) {
            ::Gitlab::Duo::CodeReview::Messages.namespace_ci_minutes_used_up_error
          },
          **%i[
            trigger_depth_exceeded trigger_breadth_exceeded trigger_chain_size_exceeded chain_root_not_human
            parent_workflow_namespace_mismatch
          ].index_with(->(_user, _project) { ::Gitlab::Duo::CodeReview::Messages.flow_chain_limit_error })
        }.freeze

        DEFAULT_FAILURE_MESSAGE = ->(_user, _project) {
          ::Gitlab::Duo::CodeReview::Messages.could_not_start_workflow_error
        }

        def initialize(user:, project:)
          @user = user
          @project = project
        end

        def resolve(reason)
          KNOWN_FAILURE_MESSAGES.fetch(reason, DEFAULT_FAILURE_MESSAGE).call(user, project)
        end

        def known_reason?(reason)
          KNOWN_FAILURE_MESSAGES.key?(reason)
        end

        private

        attr_reader :user, :project
      end
    end
  end
end
