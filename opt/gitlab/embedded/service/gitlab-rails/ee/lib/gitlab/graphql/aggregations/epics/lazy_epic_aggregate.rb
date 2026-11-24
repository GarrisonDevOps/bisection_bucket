# frozen_string_literal: true

module Gitlab
  module Graphql
    module Aggregations
      module Epics
        class LazyEpicAggregate < BaseLazyAggregate
          include ::Gitlab::Graphql::Aggregations::Epics::Constants

          attr_reader :facet, :epic_id

          PERMITTED_FACETS = [COUNT, WEIGHT_SUM, HEALTH_STATUS_SUM].freeze

          # Because facets "count", "weight_sum" and "health_status_sum" share the same db query,
          # but have a different graphql type object,
          # we can separate them and serve only the fields which are requested by the GraphQL query
          def initialize(query_ctx, epic_id, aggregate_facet, epic: nil, &block)
            @epic_id = epic_id
            @epic = epic

            error = validate_facet(aggregate_facet)
            if error
              raise ArgumentError, "#{error}. Please specify either #{COUNT}, #{HEALTH_STATUS_SUM} or #{WEIGHT_SUM}"
            end

            @facet = aggregate_facet.to_sym

            super(query_ctx, epic_id, &block)

            # Register this facet to later determine what types of data are requested
            @lazy_state[:facets] << @facet
          end

          alias_method :epic_aggregate, :execute

          private

          def initial_state
            {
              pending_ids: Set.new,
              facets: Set.new,
              tree: {}
            }
          end

          def queued_objects
            @lazy_state[:pending_ids]
          end

          def result
            aggregate_object(node)
          end

          def block_params
            [node, aggregate_object(node)]
          end

          def node
            tree[@epic_id]
          end

          def load_queued_records
            unless tree[@epic_id]
              load_records_into_tree
            end
          end

          def validate_facet(aggregate_facet)
            unless aggregate_facet.present?
              return "No aggregate facet provided."
            end

            unless PERMITTED_FACETS.include?(aggregate_facet.to_sym)
              "Invalid aggregate facet #{aggregate_facet} provided."
            end
          end

          def tree
            @lazy_state[:tree]
          end

          def load_records_into_tree
            # The record hasn't been loaded yet, so
            # hit the database with all pending IDs
            pending_ids = queued_objects.to_a

            # Fire off the db query and get the results (grouped by epic_id and facet)
            raw_epic_aggregates = Gitlab::Graphql::Loaders::BulkEpicAggregateLoader.new(
              epic_ids: pending_ids,
              count_health_status: health_status_sum_requested?
            ).execute
            create_epic_nodes(raw_epic_aggregates)
            queued_objects.clear
          end

          def create_epic_nodes(aggregate_records)
            aggregate_records.each do |epic_id, aggregates|
              next if aggregates.blank?

              tree[epic_id] = EpicNode.new(epic_id, aggregates)
            end

            relate_parents_and_children
          end

          def relate_parents_and_children
            tree.each do |_, node|
              parent = tree[node.parent_id]
              next if parent.nil?

              parent.children << node
            end
          end

          def aggregate_object(node)
            case @facet
            when COUNT
              node.aggregate_count
            when HEALTH_STATUS_SUM
              node.aggregate_health_status_sum
            else
              node.aggregate_weight_sum
            end
          end

          def health_status_sum_requested?
            @lazy_state[:facets].include?(HEALTH_STATUS_SUM)
          end
        end
      end
    end
  end
end
