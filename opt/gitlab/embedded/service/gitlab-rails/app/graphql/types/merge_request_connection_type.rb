# frozen_string_literal: true

module Types
  # rubocop: disable Graphql/AuthorizeTypes
  class MergeRequestConnectionType < Types::CountableConnectionType
    field :total_time_to_merge,
      GraphQL::Types::Float,
      null: true,
      description: 'Total sum of time to merge, in seconds, for the collection of merge requests.'

    # `experiment:` needs BaseField, but the generated `nodes` and `edges` inherit the field class
    # and must keep the gem's, which has no token scope check, so restore it after this field.
    # rubocop:disable GraphQL/FieldDefinitions -- field_class must switch around this one field
    field_class ::Types::BaseField
    field :time_limited_count,
      GraphQL::Types::Int,
      null: true,
      experiment: { milestone: '19.6' },
      description: 'Total count of the collection. Returns `null` when the count exceeds the time limit, ' \
        'which applies on GitLab.com only.'
    field_class ::GraphQL::Schema::Field
    # rubocop:enable GraphQL/FieldDefinitions

    def total_time_to_merge
      object.items.without_order.total_time_to_merge
    end

    def time_limited_count
      return count unless limit_count_time?

      fast_timeout_count
    end

    private

    def fast_timeout_count
      ApplicationRecord.with_fast_read_statement_timeout { count } # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- this is called outside a transaction
    rescue ActiveRecord::QueryCanceled => e # rubocop:disable Database/RescueQueryCanceled -- used with fast_read_statement_timeout so a large count returns null instead of failing the request
      Gitlab::ErrorTracking.log_exception(
        e,
        { Labkit::Fields::ADDITIONAL_DETAILS => 'merge_request_connection_time_limited_count' }
          .merge(count_parent_log_fields)
      )
      nil
    end

    def count_parent_log_fields
      case object.parent
      when ::Group then { Labkit::Fields::GL_NAMESPACE_ID => object.parent.id }
      when ::Project then { Labkit::Fields::GL_PROJECT_ID => object.parent.id }
      else {}
      end
    end

    def limit_count_time?
      false
    end
  end
end

Types::MergeRequestConnectionType.prepend_mod
