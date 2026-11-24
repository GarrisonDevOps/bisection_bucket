# frozen_string_literal: true

module Ai
  module ActiveContext
    module Queues
      class Code
        include ::ActiveContext::Concerns::Queue

        COLLECTION_CLASS = ::Ai::ActiveContext::Collections::Code

        DEFAULT_SHARD_LIMIT = 1000
        DEFAULT_SHARD_COUNT = 1

        TARGET_RPM_FOR_LIMITED_THROUGHPUT = 20

        class << self
          def extra_preprocess_options
            { current_model_only: true }
          end

          def number_of_shards
            return DEFAULT_SHARD_COUNT if limit_throughput?

            COLLECTION_CLASS.collection_record&.queue_shard_count || DEFAULT_SHARD_COUNT
          end

          def shard_limit
            limit = COLLECTION_CLASS.collection_record&.queue_shard_limit || DEFAULT_SHARD_LIMIT

            return [max_shard_limit, limit].min if limit_throughput?

            limit
          end

          # Throughput is limited on any non-SaaS instance (Self-Managed or Dedicated)
          # unless the configured embedding model is self-hosted, to protect
          # GitLab-managed model capacity from unbounded indexing load.
          def limit_throughput?
            return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
            return false if Rails.env.development?

            throughput_check_model = embedding_model
            return true unless throughput_check_model

            !Ai::ActiveContext::Embedding.self_hosted?(throughput_check_model[:model_type])
          end

          private

          def max_shard_limit
            TARGET_RPM_FOR_LIMITED_THROUGHPUT * embedding_model_batch_size
          end

          def embedding_model_batch_size
            Ai::ActiveContext::Embedding.embeddings_request_batch_size(
              embedding_model
            )
          end

          # The embedding model configuration to check for the queue
          # This must be overridden in the CodeBackfill queue
          def embedding_model
            COLLECTION_CLASS.collection_record&.current_indexing_embedding_model
          end
        end
      end
    end
  end
end
