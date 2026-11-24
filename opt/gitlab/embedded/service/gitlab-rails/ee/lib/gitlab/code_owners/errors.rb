# frozen_string_literal: true

module Gitlab
  module CodeOwners
    class Errors
      include Enumerable

      def initialize
        @errors = []
      end

      delegate :each, :empty?, :size, to: :errors

      def add(message, line_number)
        error = Error.new(message, line_number)

        errors.append(error)
      end

      def merge(other_errors)
        errors.concat(other_errors.entries)
      end

      private

      attr_reader :file, :errors
    end
  end
end
