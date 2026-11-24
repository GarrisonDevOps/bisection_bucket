# frozen_string_literal: true

module Ai
  module Catalog
    # Resolves the coding environment a Duo Agent Platform flow needs when its
    # workload starts.
    #
    # A flow declares the environment in one of three places:
    #
    #   - Catalog and custom flows: the `coding_environment` key of their
    #     `flow_config` definition, validated by `ai_catalog/flow_v2.json`.
    #   - Foundational flows: the `coding_environment` attribute of their
    #     `Ai::Catalog::FoundationalFlow` registry entry.
    #   - Foundational chat agents: the `coding_environment` attribute of their
    #     `Ai::FoundationalChatAgent` entry.
    #
    # The sources are consulted in that order. An absent or unrecognized
    # declaration resolves to `:full`, so a typo can only ever widen the
    # environment, never silently remove a flow's repository access.
    class CodingEnvironment
      DEFAULT = :full

      VALUES = {
        'full' => :full,
        'none' => :none
      }.freeze

      # Foundational flows that declare `none` but stay on `full` while their flag is off for the session user.
      WORKHORSE_ROLLOUTS = {
        'recommend_reviewers/v1' => ->(user) { ::Feature.enabled?(:recommend_reviewers_on_workhorse, user) },
        'workplan/v1' => ->(user) { ::Feature.enabled?(:workplan_on_workhorse, user) },
        'readiness_score/v1' => ->(user) { ::Feature.enabled?(:readiness_score_on_workhorse, user) }
      }.freeze

      class << self
        # @param workflow_definition [String, nil] the workflow's stable identity,
        #   e.g. "code_review/v1". Used to look up foundational flows.
        # @param flow_config [Hash, nil] the catalog/custom flow definition.
        # @param user [User, nil] the session's user, the actor for rollout feature flags.
        # @return [Symbol] one of the values of {VALUES}, or {DEFAULT}.
        def resolve(workflow_definition:, flow_config: nil, user: nil)
          VALUES.fetch(declared_value(workflow_definition, flow_config, user), DEFAULT)
        end

        # Single source for the coding-environment -> default runtime mapping,
        # so a new environment value is mapped in one place. This is the
        # fallback a caller's runtime choice overrides; it is not a forced
        # assignment. Returns nil for a value with no default runtime.
        # @param coding_environment [Symbol, nil] a value from {resolve}.
        # @return [Symbol, nil] :ci or :workhorse.
        def default_runtime(coding_environment)
          case coding_environment
          when :none then :workhorse
          when :full then :ci
          end
        end

        # Composes {resolve} with {default_runtime} for callers that only know
        # the workflow definition.
        # @param workflow_definition [String, nil] see {resolve}.
        # @param user [User, nil] see {resolve}.
        # @return [Symbol, nil] see {default_runtime}.
        def default_runtime_for(workflow_definition, user: nil)
          default_runtime(resolve(workflow_definition: workflow_definition, user: user))
        end

        private

        # Falls through on a missing value rather than on the absence of a
        # flow_config Hash, so a flow_config that declares nothing (or declares
        # it under a Symbol key) still reaches the foundational registry.
        def declared_value(workflow_definition, flow_config, user)
          from_flow_config(flow_config) || from_registry(workflow_definition, user)
        end

        def from_flow_config(flow_config)
          return unless flow_config.is_a?(Hash)

          flow_config['coding_environment'] || flow_config[:coding_environment]
        end

        def from_registry(workflow_definition, user)
          return if workflow_definition.blank?

          from_foundational_flow(workflow_definition, user) || from_foundational_chat_agent(workflow_definition)
        end

        def from_foundational_flow(workflow_definition, user)
          flow = FoundationalFlow.find_by_reference(workflow_definition) ||
            FoundationalFlow.find_by(display_name: workflow_definition)

          workhorse_rollout = WORKHORSE_ROLLOUTS[flow&.foundational_flow_reference]
          return 'full' if workhorse_rollout && !workhorse_rollout.call(user)

          flow&.coding_environment
        end

        def from_foundational_chat_agent(workflow_definition)
          ::Ai::FoundationalChatAgent.find_by_workflow_definition(workflow_definition)&.coding_environment
        end
      end
    end
  end
end
