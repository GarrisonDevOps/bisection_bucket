# frozen_string_literal: true

module Ai
  module ActiveContext
    class Collection < ApplicationRecord
      self.table_name = :ai_active_context_collections

      ChunkStrategyLocked = Class.new(ArgumentError)

      jsonb_accessor :metadata,
        include_ref_fields: :boolean,
        collection_class: :string

      jsonb_accessor :options,
        queue_shard_count: :integer,
        queue_shard_limit: :integer,
        chunk_strategy: :string,
        chunk_strategy_size: :integer

      belongs_to :connection, class_name: 'Ai::ActiveContext::Connection'

      validates :name, presence: true, length: { maximum: 255 }
      validates :name, uniqueness: { scope: :connection_id }
      validates :metadata, json_schema: { filename: 'ai_active_context_collection_metadata', size_limit: 16.kilobytes }
      validates :options, json_schema: { filename: 'ai_active_context_collection_options', size_limit: 2.kilobytes }
      validates :number_of_partitions, presence: true, numericality: { greater_than_or_equal_to: 1, only_integer: true }
      validates :connection_id, presence: true
      validates :chunk_strategy, presence: true, if: -> { chunk_strategy_size.present? }
      validates :chunk_strategy_size, presence: true, if: -> { chunk_strategy.present? }

      def self.find_by_id(connection, id)
        connection.collections.find_by(id: id)
      end

      def self.find_by_name(connection, name)
        connection.collections.find_by(name: name)
      end

      def partition_for(routing_value)
        ::ActiveContext::Hasher.consistent_hash(number_of_partitions, routing_value)
      end

      def update_metadata!(new_metadata)
        update!(metadata: metadata.merge(new_metadata))
      end

      def update_options!(new_options)
        if chunking_options_changing?(new_options) && current_indexing_embedding_model.present?
          raise ChunkStrategyLocked, 'chunking strategy can only be set when there is no current model'
        end

        update!(options: options.merge(new_options))
      end

      def name_without_prefix
        connection.adapter.collection_name_without_prefix(name)
      end

      def current_indexing_embedding_model
        metadata_with_indifferent_access(:current_indexing_embedding_model)
      end

      def next_indexing_embedding_model
        metadata_with_indifferent_access(:next_indexing_embedding_model)
      end

      def search_embedding_model
        metadata_with_indifferent_access(:search_embedding_model)
      end

      private

      def metadata_with_indifferent_access(key)
        metadata.with_indifferent_access[key]&.with_indifferent_access
      end

      def chunking_options_changing?(new_options)
        new_options = new_options.with_indifferent_access
        chunking_keys = %w[chunk_strategy chunk_strategy_size]

        chunking_keys.any? do |key|
          new_options.key?(key) && new_options[key] != options.with_indifferent_access[key]
        end
      end
    end
  end
end
