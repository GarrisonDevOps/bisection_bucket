# frozen_string_literal: true

require "redis"

module Labkit
  module Tracing
    module Redis
      # RedisInterceptorHelper is a helper for the RedisInterceptor. This is not a public API
      class RedisInterceptorHelper
        # For optimization, compile this once
        MASK_REDIS_RE = /^([\w{}-]+(?:\W+[\w{}-]+(?:\W+[\w{}-]+)?)?)(.?)/.freeze

        def self.call_with_tracing(command, client)
          Labkit::Tracing::TracingUtils.with_tracing(operation_name: "redis.call", tags: tags_from_command(command, client)) do |_span|
            yield
          end
        end

        def self.call_pipeline_with_tracing(pipeline, client)
          Labkit::Tracing::TracingUtils.with_tracing(operation_name: "redis.call_pipeline", tags: tags_from_pipeline(pipeline, client)) do |_span|
            yield
          end
        end

        def self.common_tags_for_client(client)
          {
            "component" => "redis",
            "span.kind" => "client",
            "redis.scheme" => client.scheme,
            "redis.host" => client.host,
            "redis.port" => client.port,
            "redis.path" => client.path,
          }
        end

        def self.tags_from_command(command, client)
          tags = common_tags_for_client(client)

          tags["redis.command"] = command_serialized(command)

          tags
        end

        def self.command_serialized(command)
          return "" unless command.is_a?(Array)
          return "" if command.empty?

          command_name, *arguments = command
          command_name ||= "nil"

          info = [command_name]
          info << sanitize_argument_for_command(command_name, arguments.first) unless arguments.empty?
          info << "...#{arguments.size - 1} more value(s)" if arguments.size > 1

          info.join(" ")
        end

        def self.tags_from_pipeline(pipeline, client)
          tags = common_tags_for_client(client)

          commands = pipeline.commands

          # Limit to the first 5 commands
          commands.first(5).each_with_index do |command, index|
            tags["redis.command.#{index}"] = command_serialized(command)
          end
          tags["redis.pipeline.commands.length"] = commands.length

          tags
        end

        # get_first_argument_for_command returns a masked value representing the first argument
        # from a redis command, taking care of certain sensitive commands
        def self.sanitize_argument_for_command(command_name, first_argument)
          return "*****" if command_is_sensitive?(command_name)

          return "nil" if first_argument.nil?
          return first_argument if first_argument.is_a?(Numeric)
          return "*****" unless first_argument.is_a?(String)

          mask_redis_arg(first_argument)
        end

        # Returns true if the arguments for the command should be masked
        def self.command_is_sensitive?(command_name)
          command_is?(command_name, :auth) || command_is?(command_name, :eval)
        end

        # Returns true if the command is equivalent to the command_symbol symbol
        def self.command_is?(command_name, command_symbol)
          if command_name.is_a?(Symbol)
            command_name == command_symbol
          else
            command_name.to_s.casecmp(command_symbol.to_s).zero?
          end
        end

        def self.mask_redis_arg(argument)
          return "" if argument.empty?

          matches = argument.match(MASK_REDIS_RE)

          matches[2].empty? ? matches[0] : matches[0] + "*****"
        end
        private_class_method :mask_redis_arg
      end
    end
  end
end
