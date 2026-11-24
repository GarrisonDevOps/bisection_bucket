# frozen_string_literal: true

module Gitlab
  module SPDX
    module ExpressionParsing
      extend ActiveSupport::Concern

      included do
        include Gitlab::Utils::StrongMemoize
      end

      private

      def parse_expression(name)
        strong_memoize_with(:parse_expression, name) do
          ExpressionParser.new(name).parse
        end
      end
    end
  end
end
