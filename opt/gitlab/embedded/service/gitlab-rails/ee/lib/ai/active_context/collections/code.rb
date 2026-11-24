# frozen_string_literal: true

module Ai
  module ActiveContext
    module Collections
      class Code
        include ::ActiveContext::Concerns::Collection

        COLLECTION_SHORT_NAME = 'code'

        def self.indexing?
          ::ActiveContext.indexing? && indexing_embedding_models_present? && feature_setting_allowed?
        end

        def self.indexing_embedding_models_present?
          indexing_embedding_models.present?
        end
        private_class_method :indexing_embedding_models_present?

        def self.feature_setting_allowed?
          return true if Ai::ActiveContext.gitlab_selects_embedding_model?

          Ai::ActiveContext::Embedding.feature_setting_allowed?(COLLECTION_SHORT_NAME)
        end

        def self.collection_name
          ::ActiveContext.adapter.full_collection_name(COLLECTION_SHORT_NAME)
        end

        def self.embedding_model_factory
          ::Ai::ActiveContext::Embeddings::ModelFactory
        end

        def self.queue
          Queues::Code
        end

        def self.backfill_queue
          Queues::CodeBackfill
        end

        def self.reference_klass
          References::Code
        end

        def self.partition_name
          collection_record.name
        end

        def self.partition_number(project_id)
          collection_record.partition_for(project_id)
        end

        def self.routing(object)
          object[:routing]
        end

        def self.track_refs!(routing:, hashes:)
          track!(hashes.map { |hash| { id: hash, routing: routing } })
        end

        def self.redact_unauthorized_results!(result)
          return result if result.user.nil?

          project_ids = result.pluck('project_id') # rubocop: disable CodeReuse/ActiveRecord -- this an enum `pluck` method, not ActiveRecord
          projects = Project.id_in(project_ids).index_by(&:id)

          result.group_by { |r| r['project_id'] }.each_with_object([]) do |(project_id, project_objects), permitted|
            project = projects[project_id]

            permitted.concat(project_objects) if project && Ability.allowed?(result.user, :read_code, project)
          end
        end
      end
    end
  end
end
