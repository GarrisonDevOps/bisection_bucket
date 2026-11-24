# frozen_string_literal: true

module Ai
  module Messaging
    # A session delegated from a messaging session (via start_flow), shown on the
    # parent's surface. The child keeps no messaging_callback_context of its own,
    # so it stays a normal project session; the surface is resolved through
    # parent_workflow instead.
    class ChildSession
      # Only needs to outlast the window in which the child's terminal event can be redelivered.
      DELIVERY_CLAIM_TTL = 1.day

      attr_reader :child

      # @param workflow [Ai::DuoWorkflows::Workflow] any session; only a delegated one resolves
      # @return [ChildSession, nil] nil unless it is shown on its parent's surface
      def self.from_workflow(workflow)
        callback_context = parent_callback_context(workflow)
        return unless callback_context

        new(workflow, ::Ai::Messaging::AdapterRegistry[callback_context['adapter']], callback_context)
      end

      # Whether the session is shown on its parent's surface, without building the adapter.
      #
      # @param workflow [Ai::DuoWorkflows::Workflow]
      # @return [Boolean]
      def self.relayed?(workflow)
        parent_callback_context(workflow).present?
      end

      # @return [Hash, nil] the parent's callback context, when its surface shows this session
      def self.parent_callback_context(workflow)
        # An explicit context gives the session a surface of its own.
        return if workflow.messaging_callback_context.present?

        parent = workflow.parent_workflow
        return unless parent
        # The parent's surface belongs to its invoker, so only their own delegated work is shown there.
        return unless workflow.user_id == parent.user_id

        callback_context = parent.messaging_callback_context
        return if callback_context.blank?

        adapter_class = ::Ai::Messaging::AdapterRegistry[callback_context['adapter']]
        return unless adapter_class&.relays_child_sessions?

        callback_context
      end
      private_class_method :parent_callback_context

      def initialize(child, adapter_class, parent_callback_context)
        @child = child
        @adapter = adapter_class.from_callback_context(parent_callback_context)
        # The parent's session state describes the parent's own messages, not the child's.
        @callback_context = parent_callback_context.except(*::Ai::Messaging::Adapters::Base::SESSION_STATE_KEYS)
      end

      # @return [Boolean] whether the surface was updated
      def render_card
        adapter.render_child_card(callback_context: callback_context, child: child)
      end

      # @return [Boolean] whether the outcome reached the surface
      def deliver_result(message:, error:)
        adapter.deliver_child_result(callback_context: callback_context, child: child, message: message, error: error)
      end

      # The child has no messaging context to hold the claim, so it lives in Redis. Claimed
      # per kind of ending, so a failed session that is retried and finishes still reports it.
      #
      # @param error [Symbol, nil] the ending being delivered, nil for success
      # @return [Boolean] true for exactly one caller until released
      def claim_result_delivery(error)
        Gitlab::Redis::SharedState.with do |redis|
          !!redis.set(delivery_claim_key(error), 1, nx: true, ex: DELIVERY_CLAIM_TTL.to_i)
        end
      end

      # @param error [Symbol, nil]
      # @return [void]
      def release_result_delivery!(error)
        Gitlab::Redis::SharedState.with { |redis| redis.del(delivery_claim_key(error)) }

        nil
      end

      private

      attr_reader :adapter, :callback_context

      def delivery_claim_key(error)
        "ai:messaging:child_session:#{child.id}:delivered:#{error || :finished}"
      end
    end
  end
end
