# frozen_string_literal: true

module Gitlab
  module Ai
    module ModelSelection
      # Namespace-level eligibility for models that need their own per-customer
      # gate, independent of whichever flag unlocks the surrounding feature (e.g.
      # bl_security_analyzer for BLSA). Each gated model has its own flag,
      # actor-scoped per top-level group via the same Flipper mechanism used
      # elsewhere in GitLab.
      module RestrictedNamespaceModels
        MYTHOS_MODEL_REFS = %w[claude_mythos_5_1 claude_mythos_5_2].freeze

        def self.namespace_eligible?(namespace, model_ref)
          return true unless namespace

          case model_ref
          when *MYTHOS_MODEL_REFS
            ::Feature.enabled?(:mythos_restricted_namespace_model, namespace.root_ancestor)
          else
            true
          end
        end
      end
    end
  end
end
