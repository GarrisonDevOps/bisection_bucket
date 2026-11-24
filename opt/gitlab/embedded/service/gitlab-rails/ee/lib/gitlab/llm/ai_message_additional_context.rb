# frozen_string_literal: true

module Gitlab
  module Llm
    class AiMessageAdditionalContext
      include ActiveModel::AttributeAssignment

      def initialize(data = [])
        @data = Array.wrap(data).map do |item_attrs|
          AiMessageAdditionalContextItem.new(item_attrs)
        end
      end

      def to_a
        @data.map(&:to_h)
      end
    end
  end
end
