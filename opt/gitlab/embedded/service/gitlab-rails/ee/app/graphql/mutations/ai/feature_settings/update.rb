# frozen_string_literal: true

module Mutations
  module Ai
    module FeatureSettings
      class Update < Base
        graphql_name 'AiFeatureSettingUpdate'
        description "Updates or creates settings for AI features."

        argument :features, [::Types::Ai::FeatureSettings::FeaturesEnum],
          required: true,
          description: 'Array of AI features being configured (for single or batch update).'

        argument :provider, ::Types::Ai::FeatureSettings::ProvidersEnum,
          required: true,
          description: 'Provider for AI setting.'

        argument :ai_self_hosted_model_id,
          ::Types::GlobalIDType[::Ai::SelfHostedModel],
          required: false,
          description: 'Global ID of the self-hosted model providing the AI setting.'

        argument :offered_model_ref, GraphQL::Types::String,
          required: false,
          description: 'Identifier of the selected model for the feature.'

        authorize_granular_token permissions: :update_ai_feature_setting,
          boundary: :instance, boundary_type: :instance

        def resolve(**args)
          check_feature_access!

          raise_argument_not_available_if!(args, :ai_self_hosted_model_id) do
            !self_hosted_models_for_features?(args[:features])
          end
          raise_argument_not_available_if!(args, :offered_model_ref) { !gitlab_models? }

          features = args[:features]

          return error_response('At least one feature is required') if features.empty?

          return error_response('Features must not contain duplicates') if features.uniq.size != features.size

          # Every GitLab-managed model selection needs the catalog, so fail once up front instead of once per feature.
          return error_response(catalog.error_message) if vendored?(args) && !catalog.success?

          upsert_args = args.dup
          upsert_args.delete(:features)

          self_hosted_model_gid = upsert_args[:ai_self_hosted_model_id]
          if self_hosted_model_gid
            upsert_args[:ai_self_hosted_model_id] = GitlabSchema.parse_gid(self_hosted_model_gid)&.model_id
          end

          results = features.map { |feature| update_model_selection(feature, upsert_args) }

          errors = results.select(&:error?).flat_map(&:errors)
          feature_settings = results.reject(&:error?).flat_map(&:payload)

          decorated_feature_settings = ::Gitlab::Graphql::Representation::AiFeatureSetting
            .decorate(feature_settings, with_self_hosted_models: self_hosted_models?,
              with_gitlab_models: gitlab_models?, model_definitions: catalog.parser)

          {
            ai_feature_settings: decorated_feature_settings,
            errors: errors
          }
        end

        private

        def dap_features
          [
            :duo_agent_platform,
            :duo_agent_platform_agentic_chat,
            :duo_developer,
            :recommend_reviewers_assign,
            :risk_classification
          ]
        end

        def error_response(message)
          { ai_feature_settings: [], errors: [message] }
        end

        def vendored?(args)
          args[:provider] == 'vendored'
        end

        def self_hosted_models_for_features?(features)
          has_dap_feature = features.any? { |feature| dap_features.include?(feature) }
          has_classic_feature = features.any? { |feature| dap_features.exclude?(feature) }

          return false if has_dap_feature && !dap_self_hosted_models?
          return false if has_classic_feature && !self_hosted_models?

          true
        end

        def dap_self_hosted_models?
          Ability.allowed?(current_user, :update_dap_self_hosted_model)
        end

        def self_hosted_models?
          Ability.allowed?(current_user, :manage_self_hosted_models_settings)
        end

        def gitlab_models?
          Ability.allowed?(current_user, :manage_instance_model_selection)
        end

        def update_model_selection(feature, args)
          ::Ai::ModelSelection::UpdateSelfManagedModelSelectionService.new(
            current_user, args.merge(feature: feature), catalog: catalog
          ).execute
        end

        def catalog
          @catalog ||= ::Ai::ModelSelection::ModelDefinitions.fetch(current_user)
        end

        def raise_argument_not_available_if!(args, attribute)
          return unless args[attribute] && yield

          raise ::Gitlab::Graphql::Errors::ArgumentError,
            format(_("You don't have permission to update the setting %{attribute}."), attribute: attribute)
        end
      end
    end
  end
end
