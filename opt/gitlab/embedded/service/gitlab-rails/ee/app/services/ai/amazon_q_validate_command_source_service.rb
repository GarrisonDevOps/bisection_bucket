# frozen_string_literal: true

module Ai
  class AmazonQValidateCommandSourceService
    UnsupportedCommandError = Class.new(StandardError)
    UnsupportedSourceError = Class.new(StandardError)
    DeprecatedCommandError = Class.new(StandardError)

    def initialize(command:, source:)
      @command = command
      @source = source
    end

    def validate
      if source.is_a?(MergeRequest) && ::Ai::AmazonQ::Commands::DEPRECATED_COMMANDS.key?(command)
        message = _(
          "/q test is now supported by using /q dev in an issue or merge request. " \
            "To generate unit tests for this MR, add an inline comment " \
            "and enter /q dev along with a comment about the tests you want written."
        )
        raise DeprecatedCommandError, message
      end

      case source
      when Issue
        command_list = ::Ai::AmazonQ::Commands::ISSUE_SUBCOMMANDS
        message = format(_("Unsupported issue command: %{command}"), command: command)
        raise UnsupportedCommandError, message unless command_list.include?(command)
      when MergeRequest
        command_list = ::Ai::AmazonQ::Commands::MERGE_REQUEST_SUBCOMMANDS
        message = format(_("Unsupported merge request command: %{command}"), command: command)
        raise UnsupportedCommandError, message unless command_list.include?(command)
      else
        raise UnsupportedSourceError, format(_("Unsupported source type: %{source_class}"), source_class: source.class)
      end
    end

    private

    attr_reader :command, :source
  end
end
