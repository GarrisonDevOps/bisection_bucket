# frozen_string_literal: true

module Gitlab
  module Llm
    module Embeddings
      class ModelDefinition
        Error = Class.new(StandardError)

        attr_reader :feature_name, :unit_primitive, :provider, :identifier, :use_cloud_aigw, :self_hosted_model

        UNIT_PRIMITIVE_GENERATE_EMBEDDINGS_CODEBASE = 'generate_embeddings_codebase'

        FEATURE_CODE_EMBEDDINGS = :embeddings_code

        PROVIDER_GITLAB = "gitlab"
        PROVIDER_LITELLM = "litellm"

        TOKEN_LIMIT_EXCEEDED_PATTERNS = {
          'text_embedding_005_vertex' => /the input token count is \d+ but the model supports up to \d+/
        }.freeze

        def self.for_gitlab_provided_code_embeddings(identifier:, use_cloud_aigw: false)
          new(
            feature_name: FEATURE_CODE_EMBEDDINGS,
            unit_primitive: UNIT_PRIMITIVE_GENERATE_EMBEDDINGS_CODEBASE,
            provider: PROVIDER_GITLAB,
            identifier: identifier,
            use_cloud_aigw: use_cloud_aigw
          )
        end

        def self.for_self_hosted_code_embedding(self_hosted_model:)
          raise Error, "given record is not a self-hosted embedding model" unless self_hosted_model&.embedding?

          new(
            feature_name: FEATURE_CODE_EMBEDDINGS,
            unit_primitive: UNIT_PRIMITIVE_GENERATE_EMBEDDINGS_CODEBASE,
            provider: PROVIDER_LITELLM,
            identifier: self_hosted_model.identifier,
            use_cloud_aigw: false,
            self_hosted_model: self_hosted_model
          )
        end

        def initialize(
          feature_name:, unit_primitive:, provider:, identifier:,
          use_cloud_aigw: false, self_hosted_model: nil
        )
          @feature_name = feature_name
          @unit_primitive = unit_primitive
          @provider = provider
          @identifier = identifier
          @use_cloud_aigw = use_cloud_aigw
          @self_hosted_model = self_hosted_model
        end

        def aigw_base_url
          @aigw_base_url ||= use_cloud_aigw ? ::Gitlab::AiGateway.cloud_connector_url : ::Gitlab::AiGateway.url
        end

        def model_params
          return custom_model_params if custom_model?

          standard_model_params
        end

        def custom_model?
          self_hosted_model.present?
        end

        def catch_token_limit_exceeded_errors?
          TOKEN_LIMIT_EXCEEDED_PATTERNS.key?(identifier)
        end

        def token_limit_exceeded_message_pattern
          TOKEN_LIMIT_EXCEEDED_PATTERNS[identifier]
        end

        def gitlab_managed?
          provider == PROVIDER_GITLAB
        end

        def litellm_drop_params?
          provider == PROVIDER_LITELLM && custom_model?
        end

        private

        def custom_model_params
          # The `name` parameter must correspond to the model family defined as `self_hosted_model.model`.
          # At this point, the model family can only be "embedding"
          {
            provider: provider,
            name: self_hosted_model.model,
            identifier: identifier,
            endpoint: self_hosted_model.endpoint,
            api_key: self_hosted_model.api_token
          }
        end

        def standard_model_params
          {
            provider: provider,
            identifier: identifier,
            feature_setting: feature_name.to_s
          }
        end
      end
    end
  end
end
