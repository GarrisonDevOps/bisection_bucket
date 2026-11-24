# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module AgentPlatform
        class ModelMetadata
          HEADER_KEY = 'x-gitlab-agent-platform-model-metadata'

          def initialize(feature_setting:, user: nil)
            @feature_setting = feature_setting
            @user = user
          end

          def execute
            @feature_setting = feature_setting.build_with_offered_model_ref(nil) if restricted_and_ineligible?

            model_metadata = ::Gitlab::Llm::AiGateway::ModelMetadata.new(feature_setting: feature_setting).to_params
            return {} unless model_metadata.present?

            if unlisted_pinned_model?
              log_unlisted_pinned_model
              model_metadata = model_metadata.merge(identifier: nil)
            end

            { HEADER_KEY => model_metadata.to_json }
          end

          private

          attr_reader :feature_setting, :user

          # A namespace-restricted model (e.g. Mythos) can become ineligible after being selected,
          # so the pinned selection is rechecked here, where every caller resolves its model.
          def restricted_and_ineligible?
            model_ref = feature_setting.try(:offered_model_ref)
            return false if model_ref.blank?

            !::Gitlab::Ai::ModelSelection::RestrictedNamespaceModels.namespace_eligible?(
              feature_setting.try(:namespace), model_ref
            )
          end

          # AI Gateway no longer gets the pinned model, so this log is the record of the settings to clean up.
          def log_unlisted_pinned_model
            Gitlab::AppLogger.info(
              message: 'Sending no model identifier for a pinned model that AI Gateway does not list',
              event: 'agent_platform_unlisted_pinned_model',
              feature: feature_setting.feature,
              pinned_model_ref: feature_setting.offered_model_ref,
              Labkit::Fields::GL_NAMESPACE_ID => feature_setting.try(:namespace_id),
              ai_component: 'model_selection'
            )
          end

          # A namespace or an instance keeps its pinned model after AI Gateway stops listing it
          # for the feature, for example when the model is removed from the feature. Without an
          # identifier, AI Gateway serves the feature's default model.
          def unlisted_pinned_model?
            return false unless feature_setting.is_a?(::Ai::ModelSelection::FeaturesConfigurable)
            return false unless feature_setting.pinned_model?

            parser = ::Ai::ModelSelection::ModelDefinitions.fetch(user).parser
            # Keep the pinned model when the definitions are not available, for example with an
            # offline license, or do not have the feature.
            return false unless parser&.definition_for_feature(feature_setting.feature)

            parser.listed_model_refs_for_feature(feature_setting.feature).exclude?(feature_setting.offered_model_ref)
          end
        end
      end
    end
  end
end
