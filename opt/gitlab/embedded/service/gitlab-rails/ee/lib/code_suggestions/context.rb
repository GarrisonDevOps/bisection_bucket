# frozen_string_literal: true

module CodeSuggestions
  class Context
    MAX_BODY_SIZE = 500_000

    def initialize(context)
      @context = context.is_a?(Array) ? context.map(&:with_indifferent_access) : context
    end

    def trimmed
      return context if context.blank?

      sum = 0
      # find first N elements that fits into the body size
      last_idx = context.find_index do |item|
        sum += item[:content].size
        sum > MAX_BODY_SIZE
      end

      return context unless last_idx

      context[...last_idx]
    end

    private

    attr_reader :context
  end
end
