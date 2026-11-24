# frozen_string_literal: true

module Gitlab
  module Graphql
    module Representation
      module ModelSelection
        # Builds the `allowList` GraphQL payload for a model-selection feature
        # setting. Shared by the namespace decorator
        # (`Gitlab::Graphql::Representation::ModelSelection::FeatureSetting`)
        # and the instance/admin decorator
        # (`Gitlab::Graphql::Representation::AiFeatureSetting`).
        #
        # The payload returns one row per offered GitLab-managed model for
        # the feature (both allowed and disallowed), so callers can render
        # the allowlist modal UI from a single query. Each row carries:
        #
        # - the offered model attributes (ref, name, provider, description,
        #   cost_indicator);
        # - `allowed`: whether the model is in the effective allowed set
        #   (stored refs unioned with the currently chosen ref, deduplicated);
        # - `currently_chosen_model_for_feature`: whether this ref is the
        #   currently chosen model for the feature (admin offered ref when
        #   set, otherwise the GitLab default ref from definitions).
        #
        # The payload and each row expose `group` so the granular-token
        # authorization directives on `AiModelSelectionAllowList` /
        # `AiModelSelectionAllowListModel` can resolve their boundary: the
        # namespace surface passes the group (`:group` boundary), the
        # instance/admin surface leaves it `nil` so the directive falls
        # through to the `:instance` boundary. `Struct#[]` keeps the rows
        # accessible by symbol key for non-GraphQL callers.
        module AllowListPayload
          module_function

          Payload = Struct.new(:enabled, :models, :group, keyword_init: true)
          Model = Struct.new(
            :ref, :name, :model_provider, :model_description, :cost_indicator,
            :requires_paid_credits, :allowed, :currently_chosen_model_for_feature, :group,
            keyword_init: true
          )

          # @param feature_setting [Ai::ModelSelection::FeaturesConfigurable]
          #   record including `Ai::ModelSelection::ModelAllowlist`
          # @param model_definition_parser
          #   [Gitlab::Ai::ModelSelection::ModelDefinitionResponseParser]
          # @param offered_models [Array<Hash>] selectable model rows already
          #   resolved by the decorator (symbol-keyed). Each row must include
          #   `ref` and the offered-model display attributes.
          # @param group [Group, nil] authorization boundary for the
          #   namespace surface; `nil` on the instance/admin surface.
          # @return [Payload] `#enabled`, `#models`, `#group`
          def build(feature_setting:, model_definition_parser:, offered_models:, group: nil)
            effective_refs = feature_setting.effective_allowed_model_refs(model_definition_parser)
            chosen_ref = feature_setting.currently_chosen_model_ref(model_definition_parser)

            Payload.new(
              enabled: feature_setting.model_allowlist_enabled,
              group: group,
              models: Array(offered_models).map do |model|
                ref = model[:ref]

                Model.new(
                  ref: ref,
                  name: model[:name],
                  model_provider: model[:model_provider],
                  model_description: model[:model_description],
                  cost_indicator: model[:cost_indicator],
                  requires_paid_credits: model[:requires_paid_credits],
                  allowed: effective_refs.include?(ref),
                  currently_chosen_model_for_feature: ref == chosen_ref,
                  group: group
                )
              end
            )
          end
        end
      end
    end
  end
end
