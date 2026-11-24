# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Governance follows how a run is executed, not which flow it is. Per-container flow
    # enablement governs what GitLab runs unattended, so it does not reach a run the
    # caller performs itself.
    #
    # Nothing the client asserts about itself feeds this classification, so client
    # execution cannot be claimed while still getting background execution.
    class FlowExecutionAuthorizer
      include Gitlab::Utils::StrongMemoize
      include Gitlab::Loggable

      # `new` is private, so the classification cannot be forged from a raw value. CLIENT
      # and BACKGROUND are for this class to hand out: do not pass them to
      # CreateWorkflowService from anywhere else.
      class Classification
        private_class_method :new

        CLIENT = new.freeze
        BACKGROUND = new.freeze

        def client_executed?
          equal?(CLIENT)
        end

        def background?
          equal?(BACKGROUND)
        end
      end

      # Conditions of Ai::Catalog::ItemConsumerPolicy that a client-executed run is
      # deliberately not subject to. Not read at runtime; enforced by the accounting
      # spec in flow_execution_authorizer_spec.rb.
      #
      # The conditions ItemConsumerPolicy delegates to, such as the AI catalog
      # entitlement behind :execute_ai_catalog_item, are waived as a class: a user may
      # run any flow definition locally, and one resembling a catalog item does not make
      # the run a use of the catalog.
      WAIVED_ITEM_CONSUMER_CONDITIONS = {
        foundational_flow_in_allowlist: 'per-container flow enablement governs unattended execution only',
        foundational_flows_available: 'the owner flows switch governs the unattended flows surface; ' \
          'a client-executed session answers to the Duo and CLI switches instead',
        pinned_version_available: 'version pinning describes what GitLab runs on the user behalf',
        pinned_version_draft: 'version pinning describes what GitLab runs on the user behalf'
      }.freeze

      # For endpoints whose callers never perform the run themselves.
      def self.for_background_caller(current_user:, container:, workflow_definition:, resolve_service_account: true)
        new(
          current_user: current_user,
          container: container,
          workflow_definition: workflow_definition,
          start_workflow: false,
          item_consumer_id: nil,
          caller_can_execute: false,
          resolve_service_account: resolve_service_account
        )
      end

      # `caller_can_execute` is a property of the endpoint, not of the request.
      # Required, so a new call site cannot silently land in the client-executed branch.
      def initialize(
        current_user:, container:, workflow_definition:,
        start_workflow:, item_consumer_id:, caller_can_execute:,
        resolve_service_account: true)
        @current_user = current_user
        @container = container
        @workflow_definition = workflow_definition
        @start_workflow = start_workflow
        @item_consumer_id = item_consumer_id
        @caller_can_execute = caller_can_execute
        @resolve_service_account = resolve_service_account
      end

      def execute
        return forbidden('GitLab Duo Chat sessions cannot be started as a CI workflow') if starting_duo_chat_in_ci?
        return allowed if chat_agent_run_with_known_executor?
        return not_governed unless flow
        return allow_ungovernable_flow unless catalog_item

        client_executed? ? authorize_client_executed : authorize_background
      end

      private

      attr_reader :current_user, :container, :workflow_definition

      def starting_duo_chat_in_ci?
        @start_workflow && ::Ai::FoundationalChatAgent.find_by_workflow_definition(workflow_definition)&.duo_chat?
      end

      def chat_agent_run_with_known_executor?
        foundational_chat_agent? && (client_executed? || @start_workflow)
      end

      def foundational_chat_agent?
        ::Ai::FoundationalChatAgent.foundational_workflow_definition?(workflow_definition)
      end

      def flow
        ::Ai::Catalog::FoundationalFlow[workflow_definition]
      end
      strong_memoize_attr :flow

      def catalog_item
        flow&.catalog_item
      end
      strong_memoize_attr :catalog_item

      def client_executed?
        return false unless @caller_can_execute
        return false if @start_workflow
        return false if @item_consumer_id.present?

        true
      end

      def authorize_background
        # A user namespace holds no flow enablement, so it fails closed.
        unless container.is_a?(::Project) || container.is_a?(::Group)
          return forbidden('This flow can only run in the background in a project or group')
        end

        item_consumer = container.configured_ai_catalog_items.direct.for_item(catalog_item).first

        unless Ability.allowed?(current_user, :execute_ai_catalog_item, item_consumer)
          return forbidden(background_refusal_message(item_consumer))
        end

        return allowed unless @resolve_service_account

        result = ::Ai::Catalog::ItemConsumers::ResolveServiceAccountService.new(
          container: container,
          item: catalog_item
        ).execute

        return forbidden(result.message) if result.error?

        allowed(service_account: result.payload.fetch(:service_account))
      end

      # Otherwise generic: the policy also checks flow maturity and feature flags, which must not be disclosed.
      def background_refusal_message(item_consumer)
        if item_consumer.nil? && Ability.allowed?(current_user, :read_ai_catalog_item_consumer, container)
          'This flow is not enabled for this project or group'
        else
          'This flow is not available, or you do not have permission to run it'
        end
      end

      # There is no item consumer to evaluate ItemConsumerPolicy against; the entitlement
      # half applies to the container. See WAIVED_ITEM_CONSUMER_CONDITIONS.
      def authorize_client_executed
        return forbidden('GitLab Duo Agent Platform is not available for this namespace') unless
          agentic_chat_allowed?

        # Generic on purpose: naming the flow's feature flag or maturity would disclose
        # unreleased feature names to anyone who can guess a flow reference.
        return forbidden('This flow is not available') unless flow_available?

        return forbidden('This flow can only be run in GitLab, not from an IDE or CLI session') if
          refuse_hosted_runner_only?

        allowed
      end

      # A gitlab_hosted_runner_only flow is built to run only through GitLab's own
      # infrastructure (see Ai::DuoWorkflow::RunnerValidator for the runner-side half of
      # this): it reads and reports on what GitLab runs on the caller's behalf, not on
      # whatever happens to be checked out on the caller's own machine. A client-executed
      # run has no GitLab-hosted runner in the loop at all, so it can never satisfy that
      # constraint; refusing it here is cheaper and clearer than letting the run start and
      # produce output nobody asked for.
      def refuse_hosted_runner_only?
        return false unless Feature.enabled?(:duo_hosted_runner_only_refusal, root_ancestor)

        !!flow.gitlab_hosted_runner_only
      end

      # Also fails closed for a user namespace, which holds no such ability.
      def agentic_chat_allowed?
        Ability.allowed?(current_user, :access_duo_agentic_chat, container)
      end
      strong_memoize_attr :agentic_chat_allowed?

      def flow_available?
        flow.available_for?(root_ancestor)
      end
      strong_memoize_attr :flow_available?

      # An item can be absent transiently (seeding is a worker-run service, not a
      # constraint); refusing would turn that into a 403 for a user.
      def allow_ungovernable_flow
        ::Gitlab::AppLogger.warn(
          build_structured_payload_labkit(
            **log_context,
            message: 'Foundational flow has no catalog item, skipping flow execution authorization'
          )
        )

        not_governed
      end

      def root_ancestor
        container.root_ancestor
      end
      strong_memoize_attr :root_ancestor

      def allowed(service_account: nil)
        # Chat is not a FoundationalFlow, so its raw workflow_definition is already canonical.
        ServiceResponse.success(payload: {
          service_account: service_account,
          execution: client_executed? ? Classification::CLIENT : Classification::BACKGROUND,
          workflow_definition: flow&.foundational_flow_reference || workflow_definition
        })
      end

      def not_governed
        ServiceResponse.success(payload: {
          service_account: nil,
          execution: nil,
          workflow_definition: flow&.foundational_flow_reference
        })
      end

      def forbidden(message = nil)
        ServiceResponse.error(message: message, reason: :forbidden)
      end

      def log_context
        {
          duo_workflow_definition: workflow_definition,
          container_type: container.class.name,
          container_id: container.id,
          root_namespace_id: root_ancestor.id
        }
      end
    end
  end
end
