# frozen_string_literal: true

module Ai
  module Messaging
    module Adapters
      class Base
        # container owns the session: project for CI runs, the user's default Duo
        # namespace for Workhorse runs. runtime overrides the inferred runtime.
        TriggerBundle = Data.define(
          :current_user, :service_account, :flow_reference,
          :flow_config_id, :flow_config_schema_version, :flow_version,
          :item_version, :project, :container, :goal, :resource,
          :additional_context, :source_branch, :runtime,
          :source_type, :source_link, :client_context
        ) do
          def initialize(
            current_user:, flow_reference:, goal:, service_account: nil, project: nil, container: project,
            flow_config_id: nil, flow_config_schema_version: nil, flow_version: nil,
            item_version: nil, resource: nil, additional_context: nil, source_branch: nil, runtime: nil,
            source_type: nil, source_link: nil, client_context: nil
          )
            super
          end
        end

        # Keys hooks write back into the persisted callback context during a session.
        # They describe one session's progression, so a new session started from
        # the same context (e.g. a restart) must not inherit them.
        SESSION_STATE_KEYS = %w[
          delivered_at started_note_id status_ts session_url workflow_id progress_cursor detached_turn turn_started
        ].freeze

        # Set for a turn ServerSideTurnWorker hands off to Workhorse, whose answer
        # CallbackWorker then delivers. Cleared per turn.
        DETACHED_TURN_KEY = 'detached_turn'

        # Set once ServerSideTurnWorker hands the turn's message to the run, so a
        # re-run of the job doesn't hand it over again. Cleared per turn.
        TURN_STARTED_KEY = 'turn_started'

        # Async path: returned instance has callback_context only, not full constructor state.
        def self.from_callback_context(_ctx)
          raise Gitlab::AbstractMethodError
        end

        def self.adapter_key
          raise Gitlab::AbstractMethodError
        end

        # Whether this surface streams live progress (plan/tool/agent updates) while
        # the flow runs. Gated at enqueue time so adapters that don't stream never
        # schedule a ProgressDeliveryWorker -- the cost is the scheduled job itself.
        # Opting in (returning true) is a capability bundle: such adapters MUST also
        # implement #on_progress.
        def self.supports_live_progress?
          false
        end

        # Whether sessions from this surface are readable only by the invoking user.
        def self.private_to_invoker?
          false
        end

        # Whether sessions delegated from this surface's sessions (via start_flow) are
        # shown on this surface. Opting in requires #render_child_card and
        # #deliver_child_result.
        def self.relays_child_sessions?
          false
        end

        # Entry point for surfaces whose flow the adapter framework runs itself
        # (@GitLabDuo and Slack): it creates the session and runs it through
        # with_lifecycle_hooks. The runtime provisions what it needs, so a
        # service-account failure arrives as the run's error reason.
        def trigger(bundle)
          runtime = bundle.runtime || ::Ai::DuoWorkflows::ExecuteRunService.runtime_for(bundle.flow_reference)

          with_lifecycle_hooks do |ctx|
            ctx['namespace_path'] = bundle.container.root_ancestor.full_path if bundle.container

            if runtime == :workhorse
              # Checked before the session row exists, so a refused run leaves none behind.
              unless ::Ai::DuoWorkflows::ExecuteRunService.supports?(:workhorse, bundle.flow_reference)
                next [unsupported_environment_error(bundle.flow_reference), nil]
              end

              result = start_workhorse_flow(bundle, ctx)
              next [result, nil] if result.error?

              workflow = result.payload[:workflow]
              # The Sidekiq job enqueued inside inherits this context, so the
              # turn's log lines carry the session id.
              result = ::Gitlab::ApplicationContext.with_context(duo_workflow_id: workflow.id.to_s) do
                ::Ai::DuoWorkflows::ExecuteRunService.new(
                  workflow, event: { type: :input, text: bundle.goal }, runtime: bundle.runtime,
                  context: { client_context: bundle.client_context }
                ).execute
              end
              # ExecuteRunService errors carry no payload; the session exists by now
              # and callers log its id from the response.
              if result.error?
                result = ServiceResponse.error(message: result.message, reason: result.reason,
                  payload: { workflow: workflow })
              end

              next [result, workflow]
            end

            result = start_ci_flow(bundle, ctx)
            [result, result.payload&.dig(:workflow)]
          end
        end

        def build_callback_context
          raise Gitlab::AbstractMethodError
        end

        # Runs the synchronous lifecycle for a flow whose execution lives in the
        # block: the block runs the flow, returns [response, workflow], and must
        # persist the callback context on the workflow so CallbackWorker can
        # deliver the result later. Execution and provisioning are the block's
        # concern, not this method's.
        #
        # on_request_received runs before build_callback_context so adapters can
        # stash state (e.g. a progress note id) into the context.
        def with_lifecycle_hooks
          ack = require_success { on_request_received }
          return ack if ack.error?

          ctx = build_callback_context
          response, workflow = yield(ctx)

          if response.success?
            handle_error { on_flow_enqueued(callback_context: ctx, workflow: workflow) }
          else
            # Claimed before reporting so a drop that follows this failure does not
            # report it again through WorkflowFailedEvent.
            workflow&.claim_messaging_callback_delivery

            handle_error do
              on_flow_failed(callback_context: ctx, error: response.reason || :execute_workflow_failed, workflow: nil)
            end
          end

          response
        end

        # Posts the flow's final answer to the surface. MUST return truthy only when the
        # message actually reached it: adapters swallow their own transport errors, so this
        # return value is CallbackWorker's only signal to re-attempt a lost delivery.
        def deliver_result(callback_context:, message:, workflow:) # rubocop:disable Lint/UnusedMethodArgument -- abstract method defines the contract for subclasses
          raise Gitlab::AbstractMethodError
        end

        def deliver_error(callback_context:, error:) # rubocop:disable Lint/UnusedMethodArgument -- abstract method defines the contract for subclasses
          raise Gitlab::AbstractMethodError
        end

        # Shows a delegated session on the parent's surface. callback_context is the
        # parent's, without its session state. Called on creation and on the child's
        # checkpoints, at least once each, so implementations MUST be idempotent.
        #
        # @param outcome [Symbol, nil] nil while the child runs; :finished, :flow_failed
        #   or :flow_stopped once it has ended
        # @return [Boolean] whether the surface was updated
        def render_child_card(callback_context:, child:, outcome: nil) # rubocop:disable Lint/UnusedMethodArgument -- abstract method defines the contract for subclasses
          raise Gitlab::AbstractMethodError
        end

        # Posts a delegated session's outcome on the parent's surface. MUST return
        # truthy only when it landed, like #deliver_result.
        #
        # @param message [String, nil] the child's final answer
        # @param error [Symbol, nil] nil on success, :flow_failed or :flow_stopped otherwise
        # @return [Boolean] whether the outcome reached the surface
        def deliver_child_result(callback_context:, child:, message:, error:) # rubocop:disable Lint/UnusedMethodArgument -- abstract method defines the contract for subclasses
          raise Gitlab::AbstractMethodError
        end

        # Per-turn callback-context keys a new turn clears so its answer isn't
        # skipped as already-delivered. Merged (nil-written, not dropped); an
        # adapter overrides to add its own per-turn keys (see Slack).
        def per_turn_reset
          { 'delivered_at' => nil, DETACHED_TURN_KEY => nil, TURN_STARTED_KEY => nil }
        end

        def on_request_received; end

        # Fires synchronously once the flow has been submitted to CI (workload
        # enqueued). The container has not finished setup yet (clone, CLI install,
        # setup scripts) and the agent is not running. Adapters that have the real
        # workflow object can persist identifiers or show a "spinning up" indicator
        # here -- but should defer user-facing "started" output to on_flow_started.
        def on_flow_enqueued(callback_context:, workflow:); end

        # Fires asynchronously when the workflow first transitions to :running
        # (created -> running), i.e. the agent has actually begun. Driven by
        # WorkflowStartedEvent -> CallbackWorker, so the adapter is reconstructed
        # via from_callback_context: only callback_context + workflow are available.
        #
        # Runs in an at-least-once worker (CallbackWorker), so implementations
        # MUST be idempotent -- guard non-idempotent side effects (e.g. posting a
        # message) on persisted state so a redelivery does not duplicate them.
        def on_flow_started(callback_context:, workflow:); end

        def on_flow_completed(callback_context:, workflow:); end

        # At-least-once delivery (CallbackWorker), so implementations MUST be idempotent.
        # Return false only when a required surface update did not land; CallbackWorker
        # then raises for a Sidekiq retry.
        def on_approval_required(callback_context:, workflow:) # rubocop:disable Lint/UnusedMethodArgument -- abstract method defines the contract for subclasses
          true
        end

        # Fires when a turn ends with the agent waiting for the user's next message.
        # At-least-once delivery (CallbackWorker), so implementations MUST be idempotent.
        def on_input_required(callback_context:, workflow:); end

        # Fires while the workflow is running, each time new progress is available,
        # paced by ProgressDeliveryWorker (coalesced: at most ~one call per
        # in-flight delivery per workflow).
        #
        # delta is an Ai::DuoWorkflows::ProgressReader::Delta carrying both views
        # of the same point in time (the flow's own ui_chat_log format):
        #   * delta.messages     -- the current cumulative snapshot. Replace
        #     surfaces (e.g. Slack, which rewrites its whole message) render from
        #     this so they keep still-current state like the active todo list even
        #     when this tick's change was an unrelated entry.
        #   * delta.new_messages -- only the entries appended since the last
        #     delivery. Append/stream surfaces that emit just what changed use this.
        # delta.empty? is false only when there is something new to deliver.
        #
        # Abstract: adapters that opt into live progress (supports_live_progress?)
        # implement this to render on their surface. Runs in an at-least-once
        # worker with replace semantics, so implementations must be idempotent --
        # re-rendering the same delta must be harmless.
        def on_progress(delta:, callback_context:, workflow:) # rubocop:disable Lint/UnusedMethodArgument -- abstract method defines the contract for subclasses
          raise Gitlab::AbstractMethodError
        end

        # workflow: nil on sync failures (Base#trigger), workflow: <obj> on async (CallbackWorker).
        # Adapters that need conditional cleanup branch on workflow.present?.
        # Always called inside safe {} by the framework, so deliver_error errors are swallowed.
        def on_flow_failed(callback_context:, error:, workflow: nil) # rubocop:disable Lint/UnusedMethodArgument -- workflow kwarg is part of the public API for subclass overrides
          deliver_error(callback_context: callback_context, error: error)
        end

        private

        def start_ci_flow(bundle, ctx)
          ::Ai::Catalog::ExecuteWorkflowService.new(
            bundle.current_user,
            runtime: :ci,
            provision_membership: true,
            container: bundle.project,
            goal: bundle.goal,
            service_account: bundle.service_account,
            flow_definition: bundle.flow_reference,
            flow_config_id: bundle.flow_config_id,
            flow_config_schema_version: bundle.flow_config_schema_version,
            flow_version: bundle.flow_version,
            item_version: bundle.item_version,
            source_branch: bundle.source_branch || bundle.project.default_branch_or_main,
            additional_context: bundle.additional_context,
            messaging_callback_context: enriched_callback_context(ctx, bundle),
            source_type: bundle.source_type,
            source_link: bundle.source_link,
            **resource_params(bundle.resource)
          ).execute
        end

        # This branch creates the session itself and then starts it, while
        # start_ci_flow delegates both to ExecuteWorkflowService. That asymmetry,
        # and the hardcoded Slack flow below, are resolved once both runtimes
        # share a create-then-run shape in
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/629005.
        def start_workhorse_flow(bundle, ctx)
          flow = ::Ai::Catalog::FoundationalFlow.slack_assistant_v1

          # No ai_catalog_item_version: that param arms the item-consumer access
          # check, which a namespace-enabled foundational flow (an
          # EnabledFoundationalFlow row, not an AI Catalog item consumer) cannot
          # satisfy. Access is gated by flow_enabled? upstream instead.
          response = ::Ai::DuoWorkflows::CreateWorkflowService.new(
            container: bundle.container,
            current_user: bundle.current_user,
            params: {
              goal: bundle.goal,
              workflow_definition: bundle.flow_reference,
              agent_privileges: flow.agent_privileges,
              pre_approved_agent_privileges: flow.pre_approved_agent_privileges,
              allow_agent_to_request_user: flow.allow_agent_to_request_user,
              environment: flow.environment,
              messaging_callback_context: enriched_callback_context(ctx, bundle),
              source_type: bundle.source_type,
              source_link: bundle.source_link,
              **resource_params(bundle.resource)
            }.compact
          ).execute

          lift_payload_reason(response)
        end

        # CreateWorkflowService reports why it refused in payload[:reason]; the
        # lifecycle hooks and the trigger-failed log read response.reason.
        def lift_payload_reason(response)
          return response if response.success? || response.reason || response.payload[:reason].blank?

          ServiceResponse.error(message: response.message, payload: response.payload, reason: response.payload[:reason])
        end

        def unsupported_environment_error(flow_reference)
          ServiceResponse.error(
            message: "The #{flow_reference} flow cannot run on Workhorse",
            reason: :unsupported_environment
          )
        end

        def link_composite_identity!(service_account, scoped_user, organization)
          return unless composite_identity_eligible?(scoped_user, organization)
          return unless service_account&.composite_identity_enforced?

          ::Gitlab::Auth::Identity.link_from_web_request(
            service_account: service_account,
            scoped_user: scoped_user
          )
        end

        def composite_identity_eligible?(user, organization)
          return false unless user
          return false if ai_settings(organization).duo_workflow_oauth_application.nil?

          true
        end

        def ai_settings(organization)
          ::Ai::Setting.for_organization_read_only(organization)
        end

        # ExecuteWorkflowService expects iid, not id.
        def resource_params(resource)
          case resource
          when Issue then { issue_id: resource.iid }
          when MergeRequest then { merge_request_id: resource.iid }
          else {}
          end
        end

        # .compact strips nil values (e.g. item_version); downstream readers
        # should treat absent keys and nil keys identically.
        def enriched_callback_context(ctx, bundle)
          ctx.merge(
            'adapter' => self.class.adapter_key,
            'service_account_id' => bundle.service_account&.id,
            'flow_reference' => bundle.flow_reference,
            'flow_config_id' => bundle.flow_config_id,
            'flow_config_schema_version' => bundle.flow_config_schema_version,
            'flow_version' => bundle.flow_version,
            'item_version' => bundle.item_version
          ).compact
        end

        def require_success
          result = yield
          result.is_a?(ServiceResponse) && result.error? ? result : ServiceResponse.success
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, adapter: self.class.name)
          ServiceResponse.error(message: e.message, reason: :hook_failed)
        end

        def handle_error
          yield
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e, adapter: self.class.name)
        end
      end
    end
  end
end
