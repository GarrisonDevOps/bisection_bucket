# frozen_string_literal: true

module Ai
  module ActiveContext
    module Embedding
      BatchSizeError = Class.new(StandardError)

      MODEL_TYPE_GITLAB_MANAGED = :gitlab_managed
      MODEL_TYPE_SELF_HOSTED = :self_hosted

      # This should be kept in sync with `ai_active_context_embedding_metadata.model_type` enum
      # in ee/app/validators/json_schemas/ai_active_context_embedding_metadata.json
      MODEL_TYPES = [
        MODEL_TYPE_GITLAB_MANAGED,
        MODEL_TYPE_SELF_HOSTED
      ].freeze

      # We arrived at `40` for the initial batch size calculation:
      #   https://gitlab.com/gitlab-org/gitlab/-/issues/551002#note_2595329124
      # This is still resulting in a non-trivial volume of token limit exceeded errors,
      #   so we pre-emptively reduce to `30`:
      #   https://gitlab.com/groups/gitlab-org/-/epics/20977#note_3096296135
      TEXT_EMBEDDING_VERTEX_BATCH_SIZE = 30
      # Use the same value for the default batch size
      DEFAULT_EMBEDDINGS_REQUEST_BATCH_SIZE = 30

      COLLECTION_FEATURE_SETTING_MAP = {
        code: 'embeddings_code'
      }.freeze

      # This lookup is only used for Gitlab-managed models.
      # The hash keys should correspond to the models defined in AIGW's `ai_gateway/model_selection/models.yml`.
      # In turn, the collection record `metadata[:model_ref]` should correspond to a key in this lookup.
      MODELS_LOOKUP = {
        'text_embedding_005_vertex' => {
          model_name: 'text-embedding-005 - Vertex',
          batch_size: TEXT_EMBEDDING_VERTEX_BATCH_SIZE
        }
      }.freeze
      private_constant :MODELS_LOOKUP

      TEST_MODELS = {
        'embedding_model_001_test' => {
          model_name: 'embedding-model-001 - TEST',
          batch_size: 100
        }
      }.freeze
      private_constant :TEST_MODELS

      # This should be kept in sync with `ai_active_context_collection_options.chunk_strategy` enum
      # in ee/app/validators/json_schemas/ai_active_context_collection_options.json
      CHUNK_STRATEGIES = [:code_bytes, :code_pre_bert].freeze

      DEFAULT_CHUNK_STRATEGY = :code_bytes
      DEFAULT_CHUNK_STRATEGY_SIZE = 1000

      def self.mapped_feature_setting(collection_name)
        COLLECTION_FEATURE_SETTING_MAP[collection_name.to_sym]
      end

      def self.has_mapped_feature_setting?(collection_name)
        !!mapped_feature_setting(collection_name)
      end

      def self.feature_setting_allowed?(collection_name)
        feature_setting_key = mapped_feature_setting(collection_name)
        return false unless feature_setting_key

        Ai::FeatureSetting.allowed_features.include?(feature_setting_key)
      end

      def self.gitlab_managed_models_lookup
        return MODELS_LOOKUP.merge(TEST_MODELS) if Gitlab.dev_or_test_env?

        MODELS_LOOKUP
      end

      def self.self_hosted_models
        ::Ai::SelfHostedModel.allowed_models_with_family(:embedding)
      end

      def self.embeddings_request_batch_size(model_metadata)
        return DEFAULT_EMBEDDINGS_REQUEST_BATCH_SIZE if model_metadata.blank?

        configured_batch_size = model_metadata[:embeddings_request_batch_size].to_i

        return self_hosted_batch_size(configured_batch_size) if self_hosted?(model_metadata[:model_type])

        # If not a Self-hosted model, assume Gitlab-managed model
        gitlab_managed_batch_size(configured_batch_size, model_metadata[:model_ref])
      end

      def self.ensure_embeddings_request_batch_size_within_limit!(batch_size, model_type:, model_ref:)
        return if self_hosted?(model_type)

        gitlab_default_batch_size = gitlab_managed_default_batch_size(model_ref)
        return if batch_size.to_i <= gitlab_default_batch_size

        raise(
          BatchSizeError,
          "embeddings request batch size for model '#{model_ref}' " \
            "must not exceed #{gitlab_default_batch_size}"
        )
      end

      def self.self_hosted_batch_size(configured_batch_size)
        configured_batch_size > 0 ? configured_batch_size : DEFAULT_EMBEDDINGS_REQUEST_BATCH_SIZE
      end
      private_class_method :self_hosted_batch_size

      def self.gitlab_managed_batch_size(configured_batch_size, model_ref)
        gitlab_default_batch_size = gitlab_managed_default_batch_size(model_ref)

        return gitlab_default_batch_size if configured_batch_size <= 0

        # A configured override may only reduce the batch size below the model's known safe maximum,
        # never exceed it, so the model's own token-limit protection is preserved.
        [configured_batch_size, gitlab_default_batch_size].min
      end
      private_class_method :gitlab_managed_batch_size

      def self.gitlab_managed_default_batch_size(model_ref)
        gitlab_managed_models_lookup[model_ref]&.fetch(:batch_size) ||
          DEFAULT_EMBEDDINGS_REQUEST_BATCH_SIZE
      end
      private_class_method :gitlab_managed_default_batch_size

      def self.valid_model_ref?(model_ref, model_type: nil)
        return self_hosted_models.find_by_id(model_ref.to_i).present? if self_hosted?(model_type)

        # If not a Self-hosted model, assume Gitlab-managed model
        gitlab_managed_models_lookup.key?(model_ref)
      end

      def self.self_hosted?(model_type)
        model_type&.to_sym == MODEL_TYPE_SELF_HOSTED
      end

      def self.attach_model_name(model_metadata)
        return if model_metadata.nil?

        model_ref = model_metadata[:model_ref]
        model_type = model_metadata[:model_type]

        model_name = if self_hosted?(model_type)
                       ::Ai::SelfHostedModel.find_by_id(model_ref.to_i)&.name
                     else
                       # If not a Self-hosted model, assume Gitlab-managed model
                       gitlab_managed_models_lookup[model_ref]&.fetch(:model_name)
                     end

        model_metadata.merge(model_name: model_name)
      end
    end
  end
end
