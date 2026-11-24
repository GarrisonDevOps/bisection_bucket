# frozen_string_literal: true
require "time"
require "date"
require "logger"
require "json"

module Labkit
  module Logging
    class JsonLogger < ::Logger
      # We should also reject log keys coming from Labkit::Context, but we cannot
      # do this without breaking clients currently. This is tracked in
      # https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/issues/35
      RESERVED_LOG_KEYS = [
        :environment,
        :host,
        :shard,
        :stage,
        :subcomponent,
        :tier,
        :type,
      ].freeze

      def self.log_level(fallback: ::Logger::DEBUG)
        ENV.fetch("GITLAB_LOG_LEVEL", fallback)
      end

      def self.exclude_context!
        @exclude_context = true
        self
      end

      def self.exclude_context?
        !!@exclude_context
      end

      def initialize(path, level: JsonLogger.log_level)
        super
      end

      def format_message(severity, timestamp, progname, message)
        data = format_data(severity, timestamp, progname, message)

        dump_json(data) << "\n"
      end

      def format_data(severity, timestamp, progname, message)
        data = default_attributes
        data[:severity] = severity
        data[:time] = timestamp.utc.iso8601(3)

        if self.class.exclude_context?
          data[Labkit::Fields::CORRELATION_ID] = Labkit::Correlation::CorrelationId.current_id
        else
          data.merge!(Labkit::Context.current.to_h)
        end

        case message
        when String
          data[:message] = message
        when Hash
          reject_reserved_log_keys!(message)
          data.merge!(message)
        end

        data
      end

      private

      def default_attributes
        {}
      end

      def dump_json(data)
        JSON.generate(data)
      end

      def reject_reserved_log_keys!(hash)
        return if ENV["RAILS_ENV"] == "production"

        reserved_keys_used = hash.transform_keys(&:to_sym).slice(*RESERVED_LOG_KEYS)
        if reserved_keys_used.any?
          raise "The following log keys used are reserved: #{reserved_keys_used.keys.join(", ")}" +
                  "\n\nUse key names that are descriptive e.g. by using a prefix."
        end
      end
    end
  end
end
