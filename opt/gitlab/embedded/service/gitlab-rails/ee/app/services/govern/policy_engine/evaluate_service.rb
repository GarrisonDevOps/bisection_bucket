# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Evaluates one trigger and project pair against the policy store.
    #
    # An engine fault fails closed, so the result is undecidable and nothing
    # is dispatched. The save-point caller decides what to do then. A fault
    # after the engine returns propagates, because a decision may already be
    # recorded or dispatched by then.
    class EvaluateService
      # policies maps each decision's policy_id to its local row, so the
      # save-point caller can attribute a refusal without a second query.
      Result = Data.define(:verdict, :decisions, :identifier, :error, :policies) do
        def initialize(verdict:, decisions: [], identifier: nil, error: nil, policies: {})
          super
        end
      end

      # A cold Rails boot exceeds the gem's own lookup timeouts, and Ruby
      # cannot interrupt the call, so these stay generous but bounded.
      LOOKUP_CONNECT_TIMEOUT_MS = 2_000
      LOOKUP_TIMEOUT_MS = 15_000

      def self.engine
        return @engine if @engine

        url = Gitlab::Glaz::GovernPolicyEngine.policy_store_url
        # Without a store URL #evaluate fails closed. This path memoizes
        # nothing, so configuration that arrives later still wins.
        return Gitlab::Glaz.govern_policy_engine unless url

        @engine = Gitlab::Glaz::GovernPolicyEngine.new(
          store_base_url: url,
          connect_timeout_ms: LOOKUP_CONNECT_TIMEOUT_MS,
          timeout_ms: LOOKUP_TIMEOUT_MS
        )
      end

      # dispatch_if is a decision predicate that bounds action dispatch alone. The
      # engine evaluates every active policy of the trigger on each call, and
      # the recording covers all of them. nil dispatches for all of them too.
      def initialize(subject:, actor:, trigger:, context: nil, dispatch_if: nil)
        raise ArgumentError, "subject must be a Project" unless subject.is_a?(Project)

        unless ::Gitlab::PolicyStore::Triggers::TYPES.include?(trigger)
          raise ArgumentError, "unknown trigger #{trigger.inspect}"
        end

        @subject = subject
        @actor = actor
        @trigger = trigger
        @context = context
        @dispatch_if = dispatch_if
      end

      def execute
        response = evaluate
        return response if response.is_a?(Result)

        processor.process(response)
      end

      private

      attr_reader :subject, :actor, :trigger

      # Returns the engine's response, or the fail-closed Result when the
      # engine faults. ArgumentError and RuntimeError are the only two it
      # raises, and both mean the evaluation is uncertain.
      def evaluate
        engine.evaluate(
          trigger: trigger,
          context: context,
          principal: "users/#{actor.id}",
          resource: "organizations/#{subject.organization_id}/projects/#{subject.id}",
          store_authorization: store_credential
        )
      rescue ArgumentError, RuntimeError => e
        # Failing closed hides the fault from the caller, so a store outage or
        # a bad token has to reach error tracking to be noticed at all.
        Gitlab::ErrorTracking.track_exception(e, subject_kind: :project, subject_id: subject.id, trigger: trigger)

        Result.new(verdict: :undecidable, error: e.message)
      end

      def processor
        DecisionProcessor.new(
          subject: subject, actor: actor, trigger: trigger, dispatch_if: @dispatch_if
        )
      end

      def engine
        self.class.engine
      end

      def context
        @context ||= ProjectSettingsContext.build(project: subject, trigger: trigger, actor: actor)
      end

      # Read per call, so a value set after boot still takes effect.
      #
      # TODO: drop this once the store issues a workload token per request
      # instead of taking one static secret.
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/633577
      def store_credential
        ENV['GLAZ_POLICY_STORE_TOKEN'].presence
      end
    end
  end
end
