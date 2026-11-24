# frozen_string_literal: true

module Gitlab
  module Scim
    class FilterParser
      FILTER_OPERATORS = %w[eq].freeze

      attr_reader :attribute, :operator, :value

      def initialize(filter)
        @attribute, @operator, @value = filter&.split(' ')
      end

      def valid?
        FILTER_OPERATORS.include?(operator) && attribute_transform.valid?
      end

      def params
        @params ||= valid? ? attribute_transform.map_to(value) : {}
      end

      private

      def attribute_transform
        @attribute_transform ||= AttributeTransform.new(attribute)
      end
    end
  end
end
