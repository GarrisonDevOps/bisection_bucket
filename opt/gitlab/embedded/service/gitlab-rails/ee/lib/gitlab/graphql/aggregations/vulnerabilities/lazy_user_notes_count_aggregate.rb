# frozen_string_literal: true

module Gitlab
  module Graphql
    module Aggregations
      module Vulnerabilities
        class LazyUserNotesCountAggregate < BaseLazyAggregate
          attr_reader :vulnerability

          def initialize(query_ctx, vulnerability)
            @vulnerability = vulnerability.respond_to?(:sync) ? vulnerability.sync : vulnerability

            super(query_ctx, vulnerability.id)
          end

          private

          def initial_state
            {
              pending_vulnerability_ids: Set.new,
              loaded_objects: {}
            }
          end

          def result
            @lazy_state[:loaded_objects][@vulnerability.id]
          end

          def queued_objects
            @lazy_state[:pending_vulnerability_ids]
          end

          def load_queued_records
            # The record hasn't been loaded yet, so
            # hit the database with all pending IDs to prevent N+1
            pending_vulnerability_ids = queued_objects.to_a

            counts = ::Note.user.count_for_vulnerability_id(pending_vulnerability_ids)

            pending_vulnerability_ids.each do |vulnerability_id|
              @lazy_state[:loaded_objects][vulnerability_id] = counts[vulnerability_id].to_i
            end

            queued_objects.clear
          end
        end
      end
    end
  end
end
