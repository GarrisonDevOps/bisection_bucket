# frozen_string_literal: true

module Gitlab
  module Llm
    module Concerns
      module AiGatewayClientConcern
        extend ActiveSupport::Concern
        include Gitlab::Utils::StrongMemoize

        # Subclasses must implement this method returning a Hash with all the needed input.
        # An `ArgumentError` can be emitted to signal an error extracting data from the `prompt_message`
        def inputs
          raise NotImplementedError
        end

        # Can be overridden by subclasses to specify the root namespace.
        # If not overridden, returns nil and namespace feature settings won't be used
        # Example: resource.try(:root_ancestor) for merge request related features
        def root_namespace
          nil
        end

        # Can be overridden by subclasses to provide the project ID for header context.
        def project_id
          nil
        end

        # Can be overridden by subclasses to provide the namespace ID for header context.
        def namespace_id
          nil
        end

        private

        def perform_ai_gateway_request!(user:, tracking_context: {})
          client = ::Gitlab::Llm::AiGateway::Client.new(
            user,
            unit_primitive_name: unit_primitive_name,
            tracking_context: tracking_context,
            namespace_id: namespace_id,
            project_id: project_id,
            governing_namespace_id: root_namespace&.id
          )

          response = client.complete_prompt(
            base_url: base_url_from_feature_setting(user),
            prompt_name: prompt_name,
            inputs: inputs,
            prompt_version: prompt_version_or_default(user),
            model_metadata: model_metadata(user),
            timeout: ai_gateway_timeout
          )

          return unless response && response.body.present? && response.success?

          body = Gitlab::Json.safe_parse(response.body)

          body.is_a?(String) ? body : body["content"]
        end

        def prompt_version_or_default(user)
          feature_setting = selected_feature_setting(user)
          is_self_hosted = feature_setting&.self_hosted? || false

          return prompt_version if prompt_version && (!is_self_hosted && !::Ai::AmazonQ.connected?)

          metadata = model_metadata(user)
          model_family = metadata&.dig(:name)
          ::Gitlab::Llm::PromptVersions.version_for_prompt(
            prompt_name,
            model_family
          )
        end

        def ai_gateway_timeout
          Gitlab::AiGateway.timeout
        end

        def base_url_from_feature_setting(user)
          selected_feature_setting(user)&.base_url || ::Gitlab::AiGateway.url
        end

        def selected_feature_setting(user)
          return unless user

          feature_name = feature_name_for_unit_primitive
          return unless feature_name

          strong_memoize_with(:selected_feature_setting, user, feature_name) do
            service_result = ::Ai::FeatureSettingSelectionService.new(
              user,
              feature_name,
              root_namespace
            ).execute

            service_result.success? ? service_result.payload : nil
          end
        end

        def feature_name_for_unit_primitive
          ::Ai::FeatureSetting.feature_name_for_unit_primitive(unit_primitive_name)
        end

        def model_metadata(user)
          strong_memoize_with(:model_metadata, user) do
            feature_setting = selected_feature_setting(user)
            # A trial can save a gated model in group settings: drop it so the gateway
            # uses its own default instead.
            feature_setting = nil if credit_gated_model?(user, feature_setting)

            ::Gitlab::Llm::AiGateway::ModelMetadata.new(feature_setting: feature_setting).to_params
          end
        end

        def credit_gated_model?(user, feature_setting)
          return false unless feature_setting

          ::Ai::ModelSelection::UserModelSelection
            .for(user, feature_setting: feature_setting)
            .credit_gated?(feature_setting.try(:offered_model_ref))
        end

        # Must be overridden by subclasses to specify the UP name.
        def unit_primitive_name
          raise NotImplementedError
        end

        # Must be overridden by subclasses to specify the prompt name.
        def prompt_name
          raise NotImplementedError
        end

        # Can be overridden by subclasses to specify the prompt template version.
        # If not overridden or returns nil, prompt_version will be set to '^1.0.0'
        def prompt_version
          nil
        end
      end
    end
  end
end
