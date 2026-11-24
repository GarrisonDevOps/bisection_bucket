# frozen_string_literal: true

module Gitlab
  module Diff
    MissingConfigurationError = Class.new(StandardError)

    # Ports for what the diff code needs from GitLab. The monolith wires them in
    # `config/initializers/0_gitlab_diff.rb`.
    #
    # Each input accepts a plain value or a callable, resolved on every read. The
    # reader passes its own arguments through to the callable. Reading an input
    # that was never set raises `Gitlab::Diff::MissingConfigurationError` naming
    # the input.
    class Configuration
      attr_writer :diff_line_code, :binary_notice, :serialize_line

      # The legacy line code for a line at the given positions in `file_path`.
      def diff_line_code(file_path, new_pos, old_pos)
        resolve(:diff_line_code, @diff_line_code, file_path, new_pos, old_pos)
      end

      # Whether `text` is Git's notice that a binary file differs.
      def binary_notice?(text)
        resolve(:binary_notice, @binary_notice, text)
      end

      # The JSON representation of a `Gitlab::Diff::Line`.
      def serialize_line(line)
        resolve(:serialize_line, @serialize_line, line)
      end

      private

      def resolve(name, value, *args)
        if value.nil?
          raise MissingConfigurationError,
            "`Gitlab::Diff` input `#{name}` is not configured. Set it with " \
              "`Gitlab::Diff.configure { |config| config.#{name} = ... }`."
        end

        value.respond_to?(:call) ? value.call(*args) : value
      end
    end

    class << self
      def configuration
        @configuration ||= Configuration.new
      end

      def configure
        yield configuration
      end
    end
  end
end
