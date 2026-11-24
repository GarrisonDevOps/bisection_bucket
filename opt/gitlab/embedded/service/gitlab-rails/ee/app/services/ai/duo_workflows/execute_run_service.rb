# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Executes the next run of a Duo session: the caller hands over a session
    # and what just happened (input arrived, a tool or plan approval was
    # decided), and the run goes to the runtime the flow's coding environment
    # implies unless the caller overrides it. Intended as the single entry
    # point every surface calls. Callers authorize the acting user; this
    # service enforces no permissions of its own.
    class ExecuteRunService
      RUNTIMES = %i[ci workhorse].freeze
      SUPPORTED_CODING_ENVIRONMENTS = {
        ci: %i[full none],
        workhorse: %i[none]
      }.freeze
      # What the flow is told about this turn's surface. Every runtime forwards
      # these to BuildAdditionalContextService.
      CONTEXT_KEYS = %i[additional_context triggering_conversation event_type client_context].freeze

      def self.runtime_for(workflow_definition, override: nil, user: nil)
        runtime = override&.to_sym
        return runtime if RUNTIMES.include?(runtime)
        return if runtime

        ::Ai::Catalog::CodingEnvironment.default_runtime_for(workflow_definition, user: user)
      end

      # The runtime a session's next run uses: the caller's override, else the flow's default for a
      # first run, else the runtime the session last ran on.
      #
      # @param workflow [Ai::DuoWorkflows::Workflow]
      # @param override [Symbol, String, nil] :ci or :workhorse
      # @return [Symbol, nil] nil when the override is unknown or nothing resolves
      def self.runtime_for_session(workflow, override: nil)
        if override || workflow.created?
          return runtime_for(workflow.workflow_definition, override: override, user: workflow.user)
        end

        workflow.last_runtime
      end

      # Whether the runtime can run the flow's coding environment. For callers that must refuse a
      # run before creating its session.
      #
      # @param runtime [Symbol, String] :ci or :workhorse
      # @param workflow_definition [String]
      # @param user [User, nil] the session's user
      # @return [Boolean]
      def self.supports?(runtime, workflow_definition, user: nil)
        coding_environment = ::Ai::Catalog::CodingEnvironment.resolve(
          workflow_definition: workflow_definition, user: user
        )

        SUPPORTED_CODING_ENVIRONMENTS.fetch(runtime.to_sym, []).include?(coding_environment)
      end

      # source_branch and provision_membership apply to CI runs only (see Runtimes::Ci).
      def initialize(workflow, event:, runtime: nil, context: {}, source_branch: nil, provision_membership: false)
        context = context.to_h
        unknown_keys = context.keys.map(&:to_sym) - CONTEXT_KEYS
        raise ArgumentError, "Unknown run context keys: #{unknown_keys.join(', ')}" if unknown_keys.any?

        @workflow = workflow
        @event = RunEvent.new(event)
        @runtime = runtime&.to_sym
        @context = context.symbolize_keys.compact
        @source_branch = source_branch
        @provision_membership = provision_membership
      end

      def execute
        @continuation = !workflow.created?

        return invalid_event unless event.valid_for?(workflow)
        return approval_with_message if event.approval_with_message?

        resolved_runtime = resolve_runtime
        return runtime_unknown unless resolved_runtime
        return runtime_mismatch(resolved_runtime) if runtime_mismatch?
        return unsupported_environment(resolved_runtime) unless supported?(resolved_runtime)

        result = resolved_runtime == :ci ? start_ci_run : start_workhorse_run
        return result if result.error?

        ServiceResponse.success(message: result.message, payload: { workflow: workflow, **result.payload })
      end

      private

      attr_reader :workflow, :event, :runtime, :context, :source_branch, :provision_membership

      def start_ci_run
        result = ::Ai::DuoWorkflows::Runtimes::Ci.new(
          workflow, params_overrides: resume_params, context: context, source_branch: source_branch,
          provision_membership: provision_membership
        ).execute

        # Reset only after the run is enqueued, so a failed start never reopens the
        # previous turn's claim. A CI turn waits for a runner and a checkout, so it
        # does not deliver before this reset in practice.
        workflow.reset_messaging_turn! if result.success? && continuation?

        result
      end

      def start_workhorse_run
        approval = event.approval? ? event.workhorse_approval : nil
        # A reply carries the user's text; the first turn passes none, so the
        # worker answers the session's own goal.
        goal = event.input? && workflow.input_required? ? event.text : nil
        # Reset before enqueueing: a fast turn could deliver before a later reset,
        # and nothing between here and perform_async can fail.
        workflow.reset_messaging_turn! if continuation?
        ::Ai::Messaging::ServerSideTurnWorker.perform_async(
          workflow.id, approval, goal, context.as_json
        )

        ServiceResponse.success
      end

      def resolve_runtime
        self.class.runtime_for_session(workflow, override: runtime)
      end

      def runtime_mismatch?
        continuation? && runtime && runtime != workflow.last_runtime
      end

      def coding_environment
        @coding_environment ||= ::Ai::Catalog::CodingEnvironment.resolve(
          workflow_definition: workflow.workflow_definition, user: workflow.user
        )
      end

      def supported?(resolved_runtime)
        self.class.supports?(resolved_runtime, workflow.workflow_definition, user: workflow.user)
      end

      # An approval answers through human_approval/human_message; an input reply
      # carries its text as the fresh goal, overriding the stale
      # DUO_WORKFLOW_GOAL in ResumeWorkflowService. Approval ignores text.
      def resume_params
        return {} unless continuation?
        return { human_approval: event.approved?, human_message: event.message } if event.approval?

        { goal: event.text }
      end

      def continuation?
        @continuation
      end

      def invalid_event
        ServiceResponse.error(message: 'The event is invalid for this workflow', reason: :invalid_event)
      end

      def approval_with_message
        ServiceResponse.error(message: RunEvent::APPROVAL_WITH_MESSAGE_ERROR, reason: :approval_with_message)
      end

      def runtime_unknown
        ServiceResponse.error(message: 'Could not resolve a runtime for this workflow', reason: :runtime_unknown)
      end

      def runtime_mismatch(resolved_runtime)
        ServiceResponse.error(
          message: "The #{resolved_runtime} runtime does not match the workflow's #{workflow.last_runtime} runtime",
          reason: :runtime_mismatch
        )
      end

      def unsupported_environment(resolved_runtime)
        ServiceResponse.error(
          message: "The #{workflow.workflow_definition} flow requires #{coding_environment} coding environment, " \
            "which #{resolved_runtime} does not support",
          reason: :unsupported_environment
        )
      end
    end
  end
end
