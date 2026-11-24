# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- authorized via parent work item
      class AgentPlanType < BaseObject
        graphql_name 'WorkItemWidgetAgentPlan'
        description 'Represents an agent plan widget.'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        # Wraps the generated `content_html_resolver` (defined below by `markdown_field`) so it
        # also tracks the agent plan read. Prepending keeps `super` pointing at the generated
        # resolver.
        module ContentHtmlTracking
          def content_html_resolver
            super.tap { track_agent_plan_read(object) }
          end
        end
        prepend ContentHtmlTracking

        # `markdown_field` takes no feature-flag argument, so the gate has to wrap its resolver.
        # It also renders nil markdown as "", but the field contract promises null.
        module ReadinessScoreFeedbackHtmlGating
          def readiness_score_feedback_html_resolver
            return unless workplan_enabled?

            super.presence
          end
        end
        prepend ReadinessScoreFeedbackHtmlGating

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        # Fires a single `work_item_agent_plan_read` internal event per (request, work item).
        # Skips when:
        # - the agent plan has no content (don't count opens of work items that never had a plan)
        # - there is no authenticated user (TrackingService requires a User)
        # - the event was already tracked for this work item in the current request
        def self.track_agent_plan_read(widget, current_user)
          return unless widget&.content.present?
          return unless current_user.is_a?(User)

          work_item = widget.work_item
          guard_key = [:agent_plan_read_tracked, work_item.id]

          if ::Gitlab::SafeRequestStore.active?
            return if ::Gitlab::SafeRequestStore[guard_key]

            ::Gitlab::SafeRequestStore[guard_key] = true
          end

          ::Gitlab::WorkItems::Instrumentation::TrackingService.new(
            work_item: work_item,
            current_user: current_user,
            event: ::Gitlab::WorkItems::Instrumentation::EventActions::AGENT_PLAN_READ,
            extra_properties: ::Gitlab::WorkItems::Instrumentation::TrackingService.plan_event_properties(work_item)
          ).execute
        end

        field :ai_planning_enabled, GraphQL::Types::Boolean,
          null: false,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Indicates whether AI planning is enabled for the work item.',
          method: :ai_planning_enabled?

        field :has_content, GraphQL::Types::Boolean,
          null: false,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.6' },
          description: 'Indicates whether the agent plan has content. ' \
            'Unlike `content`, this does not read the content itself, so it can be resolved ' \
            'for any number of work items in a single request.',
          method: :has_content?

        # The work item's agent plan content may be stored in object storage, so each call
        # to `content` or `content_html` can cost a network round-trip. We cap call count so
        # that, for example, listing many work items with their agent plans is impossible.
        field :content, GraphQL::Types::String,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Content of the agent plan. ' \
            'This field can only be resolved for one work item in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :readiness_score, GraphQL::Types::Int,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.3' },
          description: 'Readiness score of the agent plan (0-100). ' \
            'Null when the score is not yet available. ' \
            'Only available when the `workplan` feature flag is enabled.'

        # Reading this field triggers an object storage round-trip; cap to one work item per request.
        field :readiness_score_feedback, GraphQL::Types::String,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.4' },
          description: 'Markdown feedback explaining the readiness score. ' \
            'Null when no feedback is available. ' \
            'Only available when the `workplan` feature flag is enabled. ' \
            'This field can only be resolved for one work item in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :readiness_score_status, ::Types::WorkItems::Widgets::AgentPlanReadinessScoreStatusEnum, # rubocop:disable GraphQL/ExtractType -- distinct values, not a logical sub-grouping
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.6' },
          description: 'Status of the readiness score evaluation, derived from the score and the most recent ' \
            '`workplan/v1` Duo Agent Platform workflow. ' \
            'Null when the `workplan` feature flag is disabled.'

        field :generation_status, ::Types::WorkItems::Widgets::AgentPlanGenerationStatusEnum,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.4' },
          description: 'Status of the asynchronous workplan generation flow for the work item. ' \
            'Reflects the most recent `workplan/v1` Duo Agent Platform workflow, if any; creation ' \
            'of that workflow is currently gated by the `workplan` feature flag.'

        field :latest_workflow_id, ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.6' },
          directives: granular_scope_directive(
            permissions: :read_duo_workflow, boundary: :user, boundary_type: :user
          ),
          description: 'ID of the most recent `workplan/v1` Duo Agent Platform workflow for the work item. ' \
            'Null when no workplan flow has run on the work item, or when the current user cannot read ' \
            'that workflow. Creation of that workflow is currently gated by the `workplan` feature flag. ' \
            'This field can only be resolved for one work item in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :questions, ::Types::WorkItems::AgentPlanQuestionType.connection_type,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.5' },
          description: 'Questions asked by workplan flows, across every run on the work item, oldest first. ' \
            'Null when no workplan flow has run on the work item. ' \
            'Only available when the `workplan` feature flag is enabled. ' \
            'This field can only be resolved for one work item in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :open_questions_count, GraphQL::Types::Int,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.5' },
          description: 'Number of questions asked by workplan flows whose thread is not resolved, ' \
            'across every run on the work item. ' \
            'Null when no workplan flow has run on the work item. ' \
            'Only available when the `workplan` feature flag is enabled. ' \
            'This field can only be resolved for one work item in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :updated_at, ::Types::TimeType,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.6' },
          description: 'Timestamp of when the agent plan was last updated. ' \
            'Also changes when the readiness score or AI planning setting changes. ' \
            'Null when the agent plan has no content.'

        markdown_field :content_html,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          extensions: [::Gitlab::Graphql::Limit::FieldCallCount => { limit: 1 }],
          description: 'GitLab Flavored Markdown rendering of `content`. ' \
            'This field can only be resolved for one work item in any single request.' do |widget|
          widget.work_item.agent_plan
        end

        markdown_field :readiness_score_feedback_html,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          experiment: { milestone: '19.4' },
          extensions: [::Gitlab::Graphql::Limit::FieldCallCount => { limit: 1 }],
          description: 'GitLab Flavored Markdown rendering of `readiness_score_feedback`. ' \
            'Only available when the `workplan` feature flag is enabled. ' \
            'This field can only be resolved for one work item in any single request.' do |widget|
          widget.work_item.agent_plan
        end

        def content
          object.content.tap do |value|
            track_agent_plan_read(object) if value.present?
          end
        end

        def updated_at
          object.updated_at if object.has_content?
        end

        def readiness_score
          return unless workplan_enabled?

          object.readiness_score
        end

        def readiness_score_feedback
          # Guard before touching the attribute: reading it triggers an object storage round-trip.
          return unless workplan_enabled?

          object.readiness_score_feedback
        end

        def readiness_score_status
          return unless workplan_enabled?

          # Queue both loaders before syncing either, otherwise each item batches on its own.
          preloaded = agent_plan_preloaded
          workflow = latest_workplan_workflow

          ::Gitlab::Graphql::Lazy.with_value(preloaded) do
            ::Gitlab::Graphql::Lazy.with_value(workflow) { |latest| object.readiness_score_status(latest) }
          end
        end

        def generation_status
          ::Gitlab::Graphql::Lazy.with_value(latest_workplan_workflow) do |workflow|
            ::WorkItems::Widgets::AgentPlan.generation_status_for(workflow)
          end
        end

        def latest_workflow_id
          workflow = object.latest_workflow
          return unless workflow && Ability.allowed?(current_user, :read_duo_workflow, workflow)

          workflow.to_global_id
        end

        def questions
          workplan_questions&.questions
        end

        def open_questions_count
          workplan_questions&.open_count
        end

        private

        # Both status fields read the same workflow, so they share one batched query.
        def latest_workplan_workflow
          BatchLoader::GraphQL.for(object.work_item.id).batch do |work_item_ids, loader|
            ::WorkItems::Widgets::AgentPlan.latest_workplan_workflows_for(work_item_ids).each do |id, workflow|
              loader.call(id, workflow)
            end
          end
        end

        # The score lives on `work_item.agent_plan`, which the work item list doesn't preload.
        def agent_plan_preloaded
          BatchLoader::GraphQL.for(object.work_item).batch do |work_items, loader|
            ActiveRecord::Associations::Preloader.new(records: work_items, associations: :agent_plan).call
            work_items.each { |work_item| loader.call(work_item, true) }
          end
        end

        def workplan_enabled?
          Feature.enabled?(:workplan, object.work_item.namespace.root_ancestor)
        end

        def workplan_questions
          return unless project_work_item?

          questions = object.workplan_questions(current_user)
          questions if questions.any_flow_ran?
        end

        def project_work_item?
          object.work_item.project.present?
        end

        # A save is not a read: suppress tracking when fields resolve as part of a mutation
        # response or the subscription push it triggers (both select `content`/`contentHtml`).
        def track_agent_plan_read(widget)
          return if context.query.mutation? || context.query.subscription_update?

          self.class.track_agent_plan_read(widget, current_user)
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
