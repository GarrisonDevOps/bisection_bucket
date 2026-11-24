# frozen_string_literal: true

module EE
  module Types
    module IssueConnectionType
      extend ActiveSupport::Concern

      prepended do
        field :weight, GraphQL::Types::Int, null: false, description: 'Total weight of issues collection.'
      end

      def weight
        relation = object.items

        if relation.respond_to?(:reorder)
          relation = relation.without_order

          result = relation.sum(:weight)

          if relation.try(:group_values).present?
            result.values.sum
          else
            result
          end
        else
          relation.map(&:weight).compact.sum
        end
      end
    end
  end
end
