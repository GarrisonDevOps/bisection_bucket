# frozen_string_literal: true

module Ai
  module AmazonQ
    class Commands
      MERGE_REQUEST_SUBCOMMANDS = %w[dev review].freeze
      ISSUE_SUBCOMMANDS = %w[dev transform].freeze

      # Add deprecated commands for better error handling
      DEPRECATED_COMMANDS = {
        'test' => 'dev'
      }.freeze
    end
  end
end
