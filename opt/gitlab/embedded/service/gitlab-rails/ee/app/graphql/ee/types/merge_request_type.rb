# frozen_string_literal: true

module EE
  module Types
    module MergeRequestType
      extend ActiveSupport::Concern

      prepended do
        field :approvals_left, GraphQL::Types::Int,
          null: true, calls_gitaly: true,
          description: 'Number of approvals left.'

        field :approvals_required, GraphQL::Types::Int,
          calls_gitaly: true,
          null: true, description: 'Number of approvals required.'

        field :grouped_approvals_left, GraphQL::Types::Int,
          null: true, calls_gitaly: true,
          experiment: { milestone: '19.4' },
          description: 'Number of approvals left, counting Code Owner rules that share a section ' \
            'and approvers as a single rule.'

        field :grouped_approvals_required, GraphQL::Types::Int,
          null: true, calls_gitaly: true,
          experiment: { milestone: '19.4' },
          description: 'Number of approvals required, counting Code Owner rules that share a section ' \
            'and approvers as a single rule.'

        field :merge_train_car, ::Types::MergeTrains::CarType,
          null: true,
          experiment: { milestone: '17.2' },
          description: 'Represents the merge request in a merge train.'

        field :duo_dependency_bump_breaking_changes_available, GraphQL::Types::Boolean,
          null: true,
          method: :duo_dependency_bump_breaking_changes_available?,
          experiment: { milestone: '19.2' },
          description: 'Indicates whether the GitLab Duo resolve dependency bump breaking changes ' \
            'flow can be triggered for the merge request.'

        field :merge_trains_count, GraphQL::Types::Int,
          null: true,
          deprecated: {
            reason: 'Use `count` from `cars` connection on `MergeTrains::TrainType` instead',
            milestone: '17.4'
          },
          description: 'Number of merge requests in the merge train.'

        field :merge_train_index, GraphQL::Types::Int,
          null: true,
          deprecated: {
            reason: 'Use `index` on `MergeTrains::CarType` instead',
            milestone: '17.4'
          },
          description: 'Zero-based position of the merge request in the merge train. ' \
            'Returns `null` if the merge request is not in a merge train.'

        field :has_security_reports, GraphQL::Types::Boolean,
          null: false, calls_gitaly: true,
          method: :has_security_reports?,
          description: 'Indicates if the source branch has any security reports.'

        field :security_reports_up_to_date_on_target_branch, GraphQL::Types::Boolean,
          null: false, calls_gitaly: true,
          method: :security_reports_up_to_date?,
          description: 'Indicates if the target branch security reports are out of date.'

        field :approval_state, ::Types::MergeRequests::ApprovalStateType,
          null: false,
          description: 'Information relating to rules that must be satisfied to merge the merge request.'

        field :policies_overriding_approval_settings,
          type: [::Types::SecurityOrchestration::PolicyApprovalSettingsOverrideType],
          null: true,
          description: 'Approval settings that are overridden by the policies for the merge request.',
          resolver: ::Resolvers::SecurityOrchestration::PolicyApprovalSettingsOverrideResolver

        field :suggested_reviewers, ::Types::AppliedMl::SuggestedReviewersType,
          null: true,
          description: 'Suggested reviewers for merge request.'

        field :ai_suggested_reviewers, ::Types::MergeRequests::AiSuggestedReviewerType.connection_type,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'AI-recommended reviewers for the merge request. ' \
            'Returns `null` unless the recommend reviewers flow is enabled for the project.'

        field :blocking_merge_requests, ::Types::MergeRequests::BlockingMergeRequestsType,
          null: true,
          experiment: { milestone: '16.5' },
          description: 'Merge requests that block another merge request from merging.',
          resolver_method: :base_merge_request # processing is done in the GraphQL type

        field :merge_request_diffs, ::Types::MergeRequestDiffType.connection_type,
          null: true,
          experiment: { milestone: '16.2' },
          description: 'Diff versions of a merge request.'

        field :finding_reports_comparer,
          type: ::Types::Security::FindingReportsComparerType,
          null: true,
          calls_gitaly: true,
          experiment: { milestone: '16.1' },
          description: 'Vulnerability finding reports comparison reported on the merge request.',
          resolver: ::Resolvers::SecurityReport::FindingReportsComparerResolver

        field :policy_violations,
          type: ::Types::SecurityOrchestration::PolicyViolationDetailsType,
          null: true,
          description: 'Policy violations reported on the merge request. ',
          resolver: ::Resolvers::SecurityOrchestration::PolicyViolationsResolver

        field :policy_bypass_statuses,
          [::Types::SecurityOrchestration::PolicyBypassStatusType],
          null: true,
          description: 'List of bypass settings for security policies.',
          experiment: { milestone: '18.5' },
          method: :security_policies_with_bypass_settings

        field :change_requesters,
          type: ::Types::UserType.connection_type,
          null: true,
          description: 'Users that have requested changes to the merge request.'

        field :duo_workflows,
          ::Types::Ai::DuoWorkflows::WorkflowType.connection_type,
          experiment: { milestone: '18.10' },
          null: true,
          description: 'GitLab Duo Agent Platform flow sessions associated with the merge request. ' \
            'Chat sessions are excluded.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :duo_workflow_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::MergeRequestDuoWorkflowLinksResolver,
          description: 'GitLab Duo Agent Platform sessions linked to the merge request.' do
            extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
          end

        field :agent_presence, ::Types::Ai::DuoWorkflows::AgentPresenceType,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Agent attribution for a merge request created by a GitLab Duo Agent Platform session. ' \
            'Available to anyone who can read the merge request; `userPermissions.readDuoWorkflow` tells ' \
            'whether the session itself can be opened. Returns null when no session created the merge request ' \
            'or when the `agent_presence_consolidation` feature flag is disabled.'

        field :risk_assessment,
          ::Types::MergeRequests::RiskAssessmentType,
          experiment: { milestone: '19.4' },
          null: true,
          description: 'Risk assessment for the merge request. Ultimate only.'
      end

      def risk_assessment
        return unless ::Gitlab::Duo::RiskAssessment.available?(object.project)

        object.risk_assessment
      end

      def change_requesters
        return unless object.reviewer_requests_changes_feature

        object.change_requesters
      end

      def duo_workflows
        return unless object.project.licensed_feature_available?(:ai_workflows)

        object.duo_workflows.without_foundational_chat_agents.with_preloaded_associations
      end

      def agent_presence
        return unless ::Feature.enabled?(:agent_presence_consolidation, object.root_ancestor)

        BatchLoader::GraphQL.for(object.id).batch do |merge_request_ids, loader|
          workflows = agent_presence_workflows(merge_request_ids)

          merge_request_ids.each { |id| loader.call(id, workflows[id]) }
        end
      end

      def merge_train_car
        return unless merge_trains_enabled

        object.merge_train_car
      end

      # TODO: remove when field fully deprecated https://gitlab.com/groups/gitlab-org/-/epics/14560
      def merge_trains_count
        return unless merge_trains_enabled

        object.merge_train.car_count
      end

      # TODO: remove when field fully deprecated https://gitlab.com/groups/gitlab-org/-/epics/14560
      def merge_train_index
        return unless merge_trains_enabled

        object.merge_train_car&.index
      end

      def suggested_reviewers
        return unless object.project.can_suggest_reviewers?

        object.predictions
      end

      def ai_suggested_reviewers
        return unless ::Gitlab::Duo::RecommendReviewers.available?(object.project)

        assigned = object.reviewer_ids.to_set
        object.ai_suggested_reviewers
          .reject { |suggestion| assigned.include?(suggestion.user_id) }
          .sort_by(&:id)
      end

      def base_merge_request
        object
      end

      def grouped_approvals_left
        object.approval_state.grouped_approvals_left
      end

      def grouped_approvals_required
        object.approval_state.grouped_approvals_required
      end

      private

      def merge_trains_enabled
        @merge_trains_enabled ||= object.target_project.merge_trains_enabled?
      end

      # The oldest `created` link wins; `source` links are the merge request a session started from, not attribution.
      def agent_presence_workflows(merge_request_ids)
        workflow_id_by_merge_request = {}

        ::Ai::DuoWorkflows::WorkflowMergeRequest.created_for_merge_requests_order_by_id_asc(merge_request_ids)
          .each { |link| workflow_id_by_merge_request[link.merge_request_id] ||= link.workflow_id }

        workflows = ::Ai::DuoWorkflows::Workflow.id_in(workflow_id_by_merge_request.values.uniq)
          .with_preloaded_associations.index_by(&:id)

        workflow_id_by_merge_request.transform_values { |workflow_id| workflows[workflow_id] }
      end
    end
  end
end
