# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module Attributes
        extend ActiveSupport::Concern

        DEFAULT_FLOW_VERSION = '1.0.0'
        FEATURE_MATURITIES = %w[experimental beta ga].freeze
        ENVIRONMENTS = Ai::DuoWorkflows::Workflow.environments.keys.freeze
        CODING_ENVIRONMENTS = ::Ai::Catalog::CodingEnvironment::VALUES.keys.freeze
        CONTENT_RETENTIONS = %w[full metadata].freeze
        SUPPORTED_RESOURCE_TYPES = [::MergeRequest, ::Issue].freeze
        AVAILABLE_ON = %i[gitlab_com self_managed dedicated dedicated_enabled_instances].freeze

        included do
          auto_generate_ids!

          # Unique versioned identifier (e.g. "fix_pipeline/v1") used to look up the flow
          # and select its Flow Registry config in Duo Workflow Service.
          attribute :foundational_flow_reference, :string

          # User-facing name shown in the UI.
          attribute :display_name, :string

          # Name of the AI unit primitive/feature this flow is gated and tracked against.
          attribute :ai_feature, :string,
            default: "duo_agent_platform"

          # Privileges granted to a running workflow.
          attribute :agent_privileges,
            default: []

          # Subset of `agent_privileges` the flow may use without asking anyone. A
          # privilege that is granted but not pre-approved makes the flow pause and
          # request approval, so only a flow whose surface can actually collect that
          # decision should narrow this. nil means "pre-approve everything granted",
          # which is what a flow running without a human in the loop needs.
          attribute :pre_approved_agent_privileges

          attribute :required_agent_privileges

          # Whether the agent can pause execution to request human/user input.
          attribute :allow_agent_to_request_user, :boolean,
            default: false

          # Execution environment: "web", "ambient", or "cli".
          attribute :environment, :string,
            default: "ambient"

          # Maturity level ("experimental", "beta", "ga"); drives beta-only availability gating.
          attribute :feature_maturity, :string

          # Brief user-facing description of what the flow does.
          attribute :description, :string

          # Event types (e.g. mention, assign) that auto-create flow triggers for a consumer.
          attribute :triggers,
            default: []

          # A nil value means the flow has no event restrictions (any event is allowed). An empty array means the
          # flow explicitly supports no trigger events.
          attribute :supported_events

          # Resource classes (`MergeRequest`, `Issue` or both) a trigger may start this flow for. A nil value
          # means any resource, including none at all, is allowed. An empty array means no resource is accepted.
          attribute :supported_resource_types

          # JSON-schema-like filter checked before a trigger fires (e.g. only run
          # fix_pipeline on failed pipelines).
          attribute :precondition,
            default: {}

          # Filename of the flow's icon, resolved against the GitLab SVGs assets.
          attribute :avatar, :string

          # Restricts availability to groups with an Ultimate license.
          attribute :ultimate_only, :boolean,
            default: false

          # CI report artifacts the workload job should declare. When present,
          # StartWorkflowService forwards this to WorkloadDefinition#artifacts_reports
          # so the runner uploads the files after the job completes.
          # Example: { "sast" => ["gl-sast-report.json"] }
          attribute :report_artifacts,
            default: {}

          # Where the flow runs: any of :gitlab_com, :self_managed, :dedicated, and :dedicated_enabled_instances
          # (only the Dedicated instances GitLab has enabled it for; with :self_managed, also only the Self-Managed
          # instances GitLab has enabled it for). `:dedicated` comes from the instance's own setting, so a flow
          # must not rely on it alone to restrict access; use `:dedicated_enabled_instances`.
          attribute :available_on,
            default: -> { %i[gitlab_com self_managed dedicated] }

          # Name of a GitLab feature flag that gates this flow at the group level.
          # nil means the flow is available to everyone who meets the other criteria.
          attribute :feature_flag, :string

          # false: the flow needs no group enablement and no service account, because it runs on Workhorse with the
          # permissions of the user who starts it, not with composite identity. Flows that run in CI need enablement for
          # their service account. Not listed in flow settings. Stopgap until sessions carry their own flow identity.
          attribute :requires_enablement, :boolean,
            default: true

          # Flows that manage their own discussion threads can opt out of the generic
          # progress note that is otherwise posted when the flow is triggered by an
          # @mention. Defaults to false so existing flows are unaffected.
          attribute :suppress_mention_progress_note, :boolean,
            default: false

          # Broader form of the above: flows that report their own progress opt out
          # of the generic progress note on every trigger event, not just @mention.
          # Defaults to false so existing flows are unaffected.
          attribute :suppress_progress_note, :boolean,
            default: false

          # Flows whose mention-triggered replies must be internal notes on
          # non-private projects (e.g. a security assessment). Private projects
          # keep the threaded-reply UX -- see
          # EE::Notes::PostProcessService#force_internal_reply?. Defaults to
          # false so existing flows are unaffected.
          attribute :force_internal_mention_replies, :boolean,
            default: false

          # Flows that post their own "session started" note (e.g. Code Review's
          # progress note) can opt out of the generic agent-session-started system
          # note that CreateWorkflowService otherwise posts on the noteable.
          # Defaults to false so existing flows are unaffected.
          attribute :suppress_agent_session_note, :boolean,
            default: false

          attribute :reuse_open_merge_request, :boolean,
            default: false

          # Class implementing .resolve to build the workflow's goal string per trigger event type.
          attribute :goal_templates

          # Lambda resolving the GitLab resource (e.g. a merge request) a workflow
          # session should be linked to. Called with keyword arguments `project:`
          # (a `Project`) and `goal:` (a `String`, or `nil`).
          # Returns the `Noteable` object to where system notes will be added.
          attribute :noteable_resolver

          # Lambda resolving the CI pipeline a workflow session should be linked to
          # as its source (link_type: :source). Called with keyword arguments
          # `project:` (a `Project`) and `goal:` (a `String`, or `nil`).
          # Returns the `Ci::Pipeline` the flow was initiated against, or `nil`.
          attribute :source_pipeline_resolver

          # Lambda resolving the branch the workload checks out when the caller names
          # none (e.g. the merge request a goal refers to). Called with keyword arguments
          # `project:` (a `Project`) and `goal:` (a `String`, or `nil`).
          # Returns a branch name `String`, or `nil` for the default branch.
          attribute :source_branch_resolver

          # Lambda resolving the additional context a workflow sends to AIGW.
          # Called with keyword argument `runtime_context:` (an `Ai::DuoWorkflows::AdditionalContext::RuntimeContext`).
          # Returns the content `Hash` (or nil) to be sent to AIGW. Rails derives the
          # category from the flow reference (see `FoundationalFlowContextBuilder`).
          attribute :additional_context_resolver

          # Extra category the additional context is also sent under, so flow configs
          # that still read the old category keep working while they migrate.
          # nil sends the context only under the category derived from the reference.
          attribute :context_category_alias, :string

          # What kind of coding environment the flow needs when its workload starts.
          # See `Ai::Catalog::CodingEnvironment` for the accepted values and for how this
          # is resolved against a catalog flow's own `flow_config` declaration.
          attribute :coding_environment, :string,
            default: 'full'

          # Whether the flow's job may run only on a GitLab-hosted runner (on Self-Managed, which has none,
          # on the instance's own runners; see `gitlab_hosted_runner_required?`). Also forces the
          # instance image and the pinned `duo` CLI, skips the project's setup_script and
          # cache, and gates the flow claim (flow_config_id) in the websocket token.
          attribute :gitlab_hosted_runner_only, :boolean, default: false

          # Flow Registry config version used to start the workflow.
          attribute :flow_version, :string,
            default: DEFAULT_FLOW_VERSION

          # Whether a trigger may supply its own goal for an event. False while the flow
          # still reads resource identity out of the goal, in Rails or in the AI Gateway,
          # which Rails cannot see. https://gitlab.com/gitlab-org/gitlab/-/work_items/608242
          attribute :accepts_trigger_goal, :boolean, default: false

          # Whether a trigger may run the flow on a schedule. False by default, because a
          # scheduled run has no resource and some flows read the goal as a resource ID.
          attribute :schedulable, :boolean, default: false

          # Lambda validating a request to start the flow. Called with keyword arguments
          # `container:` (a `Project` or `Namespace`), `goal:` (a `String`, or `nil`),
          # `additional_context:` (the API request's additional_context `Array`; always
          # empty on trigger runs, which build their context after validation) and
          # `client_executed:` (`true` when the caller runs the flow itself).
          # Returns a `ServiceResponse`: success with the normalized goal in
          # `payload[:goal]`, or an error with a user-facing message.
          attribute :start_request_validator

          # Lambda resolving a runtime override of the flow's reference and version
          # (e.g. to route to an experimental Flow Registry config behind a feature
          # flag). Called with keyword arguments `container:` (a `Namespace` or
          # `Project`), `user:` (a `User`, or `nil`) and `additional_context:` (the
          # run's additional context envelopes, or `nil`).
          # Returns a `[foundational_flow_reference, flow_version]` Array, or `nil`
          # to use the flow's own `foundational_flow_reference` and `flow_version`.
          attribute :flow_version_resolver

          # Default filter (Ai::FlowTrigger#filter shape) copied onto the flow's
          # auto-created trigger, e.g. run only on success. {} means no filter.
          attribute :default_trigger_filter, default: {}

          # Lambda resolving a runtime override of the flow's `ai_feature`.
          # Called with keyword arguments `current_user:` (a `User`, or `nil`) and
          # `additional_context:` (the run's additional context envelopes, or `nil`).
          # Returns the `ai_feature` `String` to use, or `nil` to fall back to
          # the flow's own `ai_feature` attribute.
          attribute :ai_feature_resolver

          # Hooks to react to some session events.
          # They are dispatched off a state machine transition, so they
          # fire whichever service created the session -- and at least once, possibly
          # out of order, so they must be idempotent.
          # See doc/development/ai_features/foundational_flows.md.
          # Runs when the session is created.
          # Callable run with `resource:` once a session is created, for side effects the flow
          # needs before it runs. To refuse a run, use `start_request_validator` or
          # `run_eligibility_resolver` instead.
          attribute :on_session_created
          # Runs when the session completes.
          attribute :on_session_finished
          # Runs when the session is stopped due to a drop/failure.
          attribute :on_session_failed
          # Runs when the session is stopped by a user cancellation.
          attribute :on_session_stopped

          # Lambda deciding whether a triggered run may start, checked by
          # Ai::FlowTriggers::RunService. Called with `project:` and `resource:` (the
          # triggering resource, nil when there is none). Returns false to skip the
          # run, and logs its own reason. RunService calls
          # Ai::Catalog::Flows::ExecuteService after the check. Runs that bypass
          # RunService, like API-started runs and scheduled policy runs, are not
          # checked.
          attribute :run_eligibility_resolver

          # Hash limiting the flow to one live session per resource. nil lets sessions run side by side.
          # See doc/development/ai_features/foundational_flows.md.
          attribute :concurrency, default: -> { Concurrency.new(nil) }

          # How much of a session's content the flow lets customers read back.
          # "full" stores and shows all of it. "metadata" keeps the model's intermediate
          # output out of what GitLab stores and shows (e.g. no debug job log, no AI
          # failure summary), so only the flow's finished output reaches the customer.
          attribute :content_retention, :string,
            default: 'full'

          validates :display_name,
            :foundational_flow_reference,
            :ai_feature,
            :description,
            presence: true

          validates :coding_environment,
            inclusion: { in: CODING_ENVIRONMENTS }

          validates :content_retention,
            inclusion: { in: CONTENT_RETENTIONS }

          validates :environment,
            inclusion: { in: ENVIRONMENTS }

          validates :feature_maturity,
            presence: true,
            inclusion: { in: FEATURE_MATURITIES }

          validate :pre_approved_agent_privileges_granted
          validate :available_on_supported
          validate :required_agent_privileges_granted
          validate :runs_as_user_without_enablement

          validates :supported_resource_types,
            inclusion: { in: SUPPORTED_RESOURCE_TYPES },
            allow_nil: true

          validates :noteable_resolver, 'ai/catalog/resolver': { keywords: [:project, :goal] }
          validates :source_pipeline_resolver, 'ai/catalog/resolver': { keywords: [:project, :goal] }
          validates :source_branch_resolver, 'ai/catalog/resolver': { keywords: [:project, :goal] }
          validates :additional_context_resolver, 'ai/catalog/resolver': { keywords: [:runtime_context] }
          validates :flow_version_resolver,
            'ai/catalog/resolver': { keywords: [:container, :user, :additional_context] }
          validates :start_request_validator,
            'ai/catalog/resolver': { keywords: [:container, :goal, :additional_context, :client_executed] }
          validates :ai_feature_resolver,
            'ai/catalog/resolver': { keywords: [:current_user, :container, :additional_context] }
          validates :run_eligibility_resolver, 'ai/catalog/resolver': { keywords: [:project, :resource] }
          validates :concurrency, 'ai/catalog/concurrency': true

          validates :on_session_created, 'ai/catalog/resolver': { keywords: [:resource] }
          validates :on_session_finished, 'ai/catalog/resolver': { keywords: [:workflow] }
          validates :on_session_failed, 'ai/catalog/resolver': { keywords: [:workflow] }
          validates :on_session_stopped, 'ai/catalog/resolver': { keywords: [:workflow] }

          alias_method :reference, :foundational_flow_reference
        end

        private

        # Pre-approving an ungranted privilege would otherwise surface as a workflow
        # that fails to start, and only for flows someone happens to run. Failing
        # when the registry is first read surfaces the typo instead.
        def pre_approved_agent_privileges_granted
          extra = pre_approved_agent_privileges - agent_privileges
          return if extra.empty?

          errors.add(
            :pre_approved_agent_privileges,
            "contains privileges not in agent_privileges: #{extra.join(', ')}"
          )
        end

        def available_on_supported
          unknown = available_on - AVAILABLE_ON

          errors.add(:available_on, "can't be blank") if available_on.empty?
          errors.add(:available_on, "contains unknown values: #{unknown.join(', ')}") if unknown.any?
          return unless available_on.include?(:dedicated_enabled_instances) && available_on.include?(:dedicated)

          errors.add(:available_on, "cannot list both dedicated and dedicated_enabled_instances")
        end

        def required_agent_privileges_granted
          extra = required_agent_privileges - agent_privileges
          return if extra.empty?

          errors.add(
            :required_agent_privileges,
            "contains privileges not in agent_privileges: #{extra.join(', ')}"
          )
        end

        def runs_as_user_without_enablement
          return if requires_enablement || coding_environment == 'none'

          errors.add(:requires_enablement, "can be false only for flows with coding_environment 'none'")
        end
      end
    end
  end
end
