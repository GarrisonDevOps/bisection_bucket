# frozen_string_literal: true

module Types
  module WorkItems
    # rubocop: disable Graphql/AuthorizeTypes -- the work items in the connection are authorized
    # rubocop: disable GraphQL/GraphqlName -- connection types take their name from the node type
    class ConnectionType < Types::CountableConnectionType
      # `experiment:` needs BaseField, but the generated `nodes` and `edges` inherit the field class
      # and must keep the gem's, which has no token scope check, so restore it after this field.
      field_class ::Types::BaseField
      field :time_limited_count,
        GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Total count of the collection, or `null` when the count exceeds the time limit.' do
        argument :limit, GraphQL::Types::Int,
          required: false,
          validates: { numericality: { greater_than: 0 } },
          description: 'Limit applied to the count query, returns limit + 1. ' \
            'When not provided, returns the exact count.'
      end
      field_class ::GraphQL::Schema::Field

      def time_limited_count(limit: nil)
        ApplicationRecord.with_fast_read_statement_timeout { count(limit: limit) } # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- this is called outside a transaction
      rescue ActiveRecord::QueryCanceled => e # rubocop:disable Database/RescueQueryCanceled -- used with fast_read_statement_timeout so a slow count returns null instead of failing the request
        Gitlab::ErrorTracking.log_exception(
          e,
          { Labkit::Fields::ADDITIONAL_DETAILS => 'work_item_connection_time_limited_count' }
            .merge(count_parent_log_fields)
        )
        nil
      end

      private

      def count_parent_log_fields
        case object.parent
        when ::Namespace then { Labkit::Fields::GL_NAMESPACE_ID => object.parent.id }
        when ::Project then { Labkit::Fields::GL_PROJECT_ID => object.parent.id }
        else {}
        end
      end
    end
    # rubocop: enable GraphQL/GraphqlName
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
