# frozen_string_literal: true

require "securerandom"

require "active_support/core_ext/module/delegation"
require "active_support/core_ext/string/starts_ends_with"
require "active_support/core_ext/string/inflections"
require "active_support/core_ext/object/blank"

require_relative "fields"

module Labkit
  # A context can be used to provide structured information on what resources
  # GitLab is working on within a service.
  #
  # Values can be provided by passing a hash. If one of the values is a Proc
  # the proc will only be called when the value is actually needed.
  #
  # Multiple contexts can be nested, the nested context will inherit the values
  # from the closest outer one.
  # All contexts will have the same correlation id.
  #
  # Usage:
  #   Labkit::Context.with_context(user: 'username', root_namespace: -> { get_root_namespace } do |context|
  #     logger.info(context.to_h)
  #   end
  #
  class Context
    # The meta log key is used to effectively aggregate
    # the attributes that we should be associating with
    # the logs that we emit.
    # These fields will get propagated across all services
    # which will allow us to correlate logs across these
    # different services.
    LOG_KEY = "meta"
    RAW_KEYS = [Fields::CORRELATION_ID].freeze

    class << self
      def with_context(attributes = {})
        context = push(attributes)

        begin
          yield(context)
        ensure
          pop(context)
        end
      end

      def push(new_attributes = {})
        new_context = current&.merge(new_attributes) || new(new_attributes)

        contexts.push(new_context)

        new_context
      end

      def pop(context)
        contexts.pop while contexts.include?(context)
      end

      def correlation_id
        contexts.last&.correlation_id
      end

      def current
        contexts.last
      end

      def clear
        Thread.current[:labkit_contexts] = nil
      end

      def log_key(key)
        key = key.to_s
        return key if RAW_KEYS.include?(key)
        return key if key.starts_with?("#{LOG_KEY}.")

        "#{LOG_KEY}.#{key}"
      end

      private

      def contexts
        Thread.current[:labkit_contexts] ||= []
      end
    end

    def initialize(values = {})
      @data = {}

      assign_attributes(values)
    end

    def merge(new_attributes)
      new_context = self.class.new(data.dup)
      new_context.assign_attributes(new_attributes)

      new_context
    end

    def to_h
      expand_data
    end

    def correlation_id
      data[Fields::CORRELATION_ID]
    end

    def get_attribute(attribute)
      raw = call_or_value(data[log_key(attribute)])

      call_or_value(raw)
    end

    protected

    def assign_attributes(attributes)
      attributes = attributes.transform_keys(&method(:log_key))

      data.merge!(attributes)

      # Remove keys that had their values set to `nil` in the new attributes
      data.keep_if { |_, value| valid_data?(value) }

      # Assign a correlation if it was missing in the first context or when
      # explicitly removed
      data[Fields::CORRELATION_ID] ||= new_id

      data
    end

    private

    delegate :log_key, to: :class

    attr_reader :data

    def call_or_value(value)
      value.respond_to?(:call) ? value.call : value
    end

    def expand_data
      data.transform_values do |value|
        value = call_or_value(value)

        value if valid_data?(value)
      end.compact
    end

    def new_id
      SecureRandom.hex
    end

    def valid_data?(value)
      value == false || value.present?
    end
  end
end
