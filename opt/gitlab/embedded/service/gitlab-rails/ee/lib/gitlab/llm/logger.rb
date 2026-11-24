# frozen_string_literal: true

module Gitlab
  module Llm
    class Logger < ::Gitlab::JsonLogger
      def self.file_name_noext
        'llm'
      end

      def self.log_level
        Gitlab::Utils.to_boolean(ENV['LLM_DEBUG']) ? ::Logger::DEBUG : ::Logger::INFO
      end

      def conditional_info(user, message:, klass:, event_name:, ai_component:, namespace: nil, **options)
        # :expanded_ai_logging is only meant for use in gitlab.com
        # For expanded logging in self-hosted Duo instances, in both Rails logs and AIGW logs, we
        # should use the instance setting.
        options[:user_id] = user&.id
        if should_log_expanded?(user, namespace: namespace)
          info(message: message, klass: klass, event_name: event_name, ai_component: ai_component, **options)
        else
          info(message: message, klass: klass, event_name: event_name, ai_component: ai_component,
            user_id: options[:user_id])
        end
      end

      def info(message:, klass:, event_name:, ai_component:, **options)
        options.merge!(message: message, class: klass, ai_event_name: event_name, ai_component: ai_component)
        super(options)
      end

      def error(message:, klass:, event_name:, ai_component:, **options)
        options.merge!(message: message, class: klass, ai_event_name: event_name, ai_component: ai_component)
        super(options)
      end

      def debug(message:, klass:, event_name:, ai_component:, **options)
        options.merge!(message: message, class: klass, ai_event_name: event_name, ai_component: ai_component)
        super(options)
      end

      def warn(message:, klass:, event_name:, ai_component:, **options)
        options.merge!(message: message, class: klass, ai_event_name: event_name, ai_component: ai_component)
        super(options)
      end

      private

      def dump_json(data)
        super(parameter_filter.filter(data))
      end

      def parameter_filter
        @parameter_filter ||= ActiveSupport::ParameterFilter.new([/\Aapi_key\z/i])
      end

      def should_log_expanded?(user, namespace: nil)
        # Instance setting takes precedence (for self-hosted instances)
        return true if ::Gitlab::CurrentSettings.enabled_expanded_logging

        # Check if the feature flag is enabled for the user - this overrides namespace check
        return true if Feature.enabled?(:expanded_ai_logging, user)

        # Namespace setting (when provided)
        return namespace.ai_usage_data_collection_enabled if namespace

        false
      end
    end
  end
end
