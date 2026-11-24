require "open3"

require "github/markup/implementation"

module GitHub
  module Markup
    class CommandError < RuntimeError
    end

    class CommandImplementation < Implementation
      DEFAULT_GITLAB_MARKUP_TIMEOUT = '10'.freeze

      attr_reader :command, :block, :name

      def initialize(regexp, command, name, &block)
        super regexp
        @command = command.to_s
        @block = block
        @name = name
      end

      def render(content)
        rendered = execute(command, content)
        rendered = rendered.to_s.empty? ? content : rendered
        call_block(rendered, content)
      end

      private

      def call_block(rendered, content)
        if block && block.arity == 2
          block.call(rendered, content)
        elsif block
          block.call(rendered)
        else
          rendered
        end
      end

      def timeout_in_seconds
        ENV.fetch('GITLAB_MARKUP_TIMEOUT', DEFAULT_GITLAB_MARKUP_TIMEOUT).to_i
      end

      def prepend_command_timeout_prefix(command)
        timeout_command_prefix = "timeout -s KILL #{timeout_in_seconds}"

        # Preserve existing support for command being either a String or an Array
        if command.is_a?(String)
          "#{timeout_command_prefix} #{command}"
        else
          timeout_command_prefix.split(' ') + command
        end
      end

      def execute(command, target)
        command_with_timeout_prefix = prepend_command_timeout_prefix(command)
        stdout_str, stderr_str, status = Open3.capture3(*command_with_timeout_prefix, stdin_data: target)
        if status.success?
          sanitize(stdout_str, target.encoding)
        elsif status.termsig == Signal.list['KILL']
          raise TimeoutError.new("Command was killed, probably due to exceeding GITLAB_MARKUP_TIMEOUT limit of #{timeout_in_seconds} seconds")
        else
          raise CommandError.new(stderr_str.strip)
        end
      end

      def sanitize(input, encoding)
        input.gsub("\r", '').force_encoding(encoding)
      end

    end
  end
end
