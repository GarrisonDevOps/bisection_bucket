# frozen_string_literal: true

module Orderable # rubocop:disable Gitlab/BoundedContexts -- general purpose concern
  extend ActiveSupport::Concern

  included do
    scope :order_by_primary_key, -> { order(*Array(primary_key).map { |key| arel_table[key] }) }
    scope :keyset_order_by_primary_key, ->(sort_order = 'asc') {
      keyset_order = Gitlab::Pagination::Keyset::Order.build(
        Array(primary_key).map do |key|
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: key,
            order_expression: sort_order == 'asc' ? arel_table[key.to_sym].asc : arel_table[key.to_sym].desc)
        end
      )

      order(keyset_order)
    }

    # By default, only support generic ordering on primary keys as they're always indexed
    def self.supported_keyset_orderings
      Array(primary_key).index_with { |_k| [:asc, :desc] }.symbolize_keys
    end
  end
end
