# frozen_string_literal: true

module Gitlab
  module CodeOwners
    class Error
      # `Error::new` takes 2 arguments.
      #
      # `message` (Symbol): the type of error that was found.
      # `line_number` (Integer): the line which the error is assigned to.
      #
      # `messages` should be one of the following:
      #
      # :invalid_approval_requirement
      # :invalid_entry_owner_format
      # :invalid_section_format
      # :invalid_section_owner_format
      # :malformed_entry_owner
      # :missing_entry_owner
      # :missing_section_name
      # :owner_without_permission
      #
      def initialize(message, line_number)
        @message = message
        @line_number = line_number
      end

      attr_reader :message, :line_number

      def ==(other)
        return true if equal?(other)

        message == other.message && line_number == other.line_number
      end
    end
  end
end
