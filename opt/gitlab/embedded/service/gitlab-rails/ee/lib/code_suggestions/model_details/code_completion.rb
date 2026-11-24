# frozen_string_literal: true

module CodeSuggestions
  module ModelDetails
    class CodeCompletion < Base
      include ::Ai::ModelSelection::Concerns::GitlabDefaultModelParams

      FEATURE_SETTING_NAME = 'code_completions'

      # We do remapping when we need to deprecate some models
      MODELS_REMAPPING = {
        'codestral_2501_vertex' => 'codestral_2508_vertex'
      }.freeze

      def initialize(current_user:, root_namespace: nil)
        super(
          current_user: current_user, feature_setting_name: FEATURE_SETTING_NAME,
          unit_primitive_name: :complete_code, root_namespace: root_namespace
        )
      end

      # Returns model details for using direct connection in the IDE.
      # When a customer has "pinned" a model via model selection, the pinned model
      # details are returned via params_from_feature_setting.
      # For customers on "GitLab Default", the Rails monolith decides the default
      # model here, not the AI Gateway's `unit_primitives.yml` file.
      def current_model
        # if self-hosted, the model details are provided by the client
        return {} if self_hosted?

        return params_from_feature_setting(feature_setting) if feature_setting&.try(:pinned_model?)

        fireworks_codestral_model_details
      end

      def pinned_model_metadata
        return if self_hosted?
        return unless feature_setting&.try(:pinned_model?)

        metadata = ::Gitlab::Llm::AiGateway::ModelMetadata.new(feature_setting: feature_setting).to_params
        remap_model_metadata(metadata)
      end

      def remap_model(params)
        if params[:model_provider] == "gitlab" && MODELS_REMAPPING.key?(params[:model_name])
          params[:model_name] = MODELS_REMAPPING[params[:model_name]]
        end

        params
      end

      def remap_model_metadata(metadata)
        return metadata unless metadata[:provider].to_s == 'gitlab'
        return metadata unless MODELS_REMAPPING.key?(metadata[:identifier])

        metadata.merge(identifier: MODELS_REMAPPING[metadata[:identifier]])
      end

      private

      def fireworks_codestral_model_details
        {
          model_provider: 'fireworks_ai',
          model_name: 'codestral-2508'
        }
      end

      def params_from_feature_setting(feature_setting)
        # Remapping the model here is necessary for direct-access-token
        remap_model({
          model_provider: "gitlab",
          model_name: feature_setting.offered_model_ref.to_s
        })
      end
    end
  end
end
