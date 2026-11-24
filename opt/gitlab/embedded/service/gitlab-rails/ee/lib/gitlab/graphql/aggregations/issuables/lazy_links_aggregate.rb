# frozen_string_literal: true

module Gitlab
  module Graphql
    module Aggregations
      module Issuables
        class LazyLinksAggregate < BaseLazyAggregate
          attr_reader :issuable_id, :link_type

          def initialize(query_ctx, issuable_id, link_type: :blocked, &block)
            @issuable_id = issuable_id
            @link_type = link_type.to_s
            @block = block

            super(query_ctx, issuable_id, &block)
          end

          alias_method :links_aggregate, :execute

          private

          def initial_state
            {
              pending_ids: { 'blocked' => Set.new, 'blocking' => Set.new },
              loaded_objects: { 'blocked' => {}, 'blocking' => {} }
            }
          end

          def result
            @lazy_state[:loaded_objects][link_type][@issuable_id]
          end

          def queued_objects
            @lazy_state[:pending_ids][@link_type]
          end

          def block_params
            result
          end

          def load_queued_records
            # The record hasn't been loaded yet, so
            # hit the database with all pending IDs to prevent N+1
            grouped_ids_row = "#{link_type}_#{issuable_type}_id"
            pending_ids = queued_objects.to_a
            builder = link_class.method("#{link_type}_issuables_for_collection")
            data = builder.call(pending_ids).compact.flatten

            data.each do |row|
              issuable_id = row[grouped_ids_row]
              @lazy_state[:loaded_objects][link_type][issuable_id] = row.count
            end

            queued_objects.clear
          end

          def link_class
            raise NotImplementedError
          end

          def issuable_type
            link_class.issuable_type
          end
        end
      end
    end
  end
end
