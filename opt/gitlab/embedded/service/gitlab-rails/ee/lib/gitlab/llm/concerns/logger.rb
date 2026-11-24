# frozen_string_literal: true

module Gitlab
  module Llm
    module Concerns
      module Logger
        Attribute = Struct.new(:name, :type)

        RESERVED_OPTIONS =
          [
            Attribute.new(:message, String),
            Attribute.new(:klass, String),
            Attribute.new(:ai_event_name, String),
            Attribute.new(:ai_component, String),
            Attribute.new(:user_id, Object),
            Attribute.new(:resource_id, Object),
            Attribute.new(:resource_class, String),
            Attribute.new(:request_id, String),
            Attribute.new(:root_namespace_id, Object),
            Attribute.new(:action_name, Symbol),
            Attribute.new(:options, Object),
            Attribute.new(:client_subscription_id, String),
            Attribute.new(:completion_service_name, String),
            Attribute.new(:llm_answer_content, String),
            Attribute.new(:duo_chat_error_code, String),
            Attribute.new(:ai_error_code, String),
            Attribute.new(:error, String),
            Attribute.new(:source, String),
            Attribute.new(:response_from_llm, String),
            Attribute.new(:url, String),
            Attribute.new(:body, String),
            Attribute.new(:timeout, String),
            Attribute.new(:stream, String),
            Attribute.new(:ai_request_type, String),
            Attribute.new(:unit_primitive, String),
            Attribute.new(:duo_chat_tool, String),
            Attribute.new(:prompt, String),
            Attribute.new(:error_message, String),
            Attribute.new(:picked_tool, String),
            Attribute.new(:allowed, String),
            Attribute.new(:tool_name, String),
            Attribute.new(:react_turn, Integer),
            Attribute.new(:ai_event, String),
            Attribute.new(:params, String),
            Attribute.new(:status, Integer),
            Attribute.new(:latency_seconds, Float),
            Attribute.new(:event_json_size, Integer),
            Attribute.new(:event_type, String),
            Attribute.new(:error_type, String),
            Attribute.new(:fragment, String),
            Attribute.new(:ai_response_server, String),
            Attribute.new(:graphql_query, String),
            Attribute.new(:graphql_query_string, String),
            Attribute.new(:graphql_variables, Object),
            Attribute.new(:token_usage, Array),
            Attribute.new(:rate_limit, String)
          ].freeze

        def self.included(base)
          base.extend ClassMethods
        end

        module ClassMethods
          def log_conditional_info(user, message:, event_name:, ai_component:, namespace: nil, **options)
            validate_options!(options)

            logger.conditional_info(user, message: message, klass: to_s, event_name: event_name,
              ai_component: ai_component, namespace: namespace, **options)
          end

          def log_info(message:, event_name:, ai_component:, **options)
            validate_options!(options)

            logger.info(message: message, event_name: event_name, klass: to_s, ai_component: ai_component, **options)
          end

          def log_error(message:, event_name:, ai_component:, **options)
            validate_options!(options)

            logger.error(message: message, event_name: event_name, klass: to_s, ai_component: ai_component, **options)
          end

          def logger
            Gitlab::Llm::Logger.build
          end

          def validate_options!(options)
            unknown_attributes = options.keys - RESERVED_OPTIONS.map(&:name)

            raise ArgumentError, "#{unknown_attributes} are not known keys" if unknown_attributes.any?

            options.each do |key, value|
              validated_option = RESERVED_OPTIONS.find { |attribute| attribute.name == key }
              next if value.nil? || value.is_a?(validated_option.type)

              logger.warn(message: "Invalid type for #{key}", event_name: 'invalid_type', value_klass: value.class.to_s,
                ai_component: 'logging', klass: to_s)
            end
          end
        end

        private

        def logger
          @logger ||= Gitlab::Llm::Logger.build
        end

        def log_conditional_info(user, message:, event_name:, ai_component:, namespace: nil, **options)
          logger.conditional_info(user,
            message: message,
            klass: self.class.to_s,
            event_name: event_name,
            ai_component: ai_component,
            namespace: namespace,
            **options)
        end

        def log_info(message:, event_name:, ai_component:, **options)
          validate_options!(options)
          logger.info(message: message,
            klass: self.class.to_s,
            event_name: event_name,
            ai_component: ai_component,
                      **options)
        end

        def log_debug(message:, event_name:, ai_component:, **options)
          validate_options!(options)

          logger.debug(message: message,
            klass: self.class.to_s,
            event_name: event_name,
            ai_component: ai_component,
                       **options)
        end

        def log_error(message:, event_name:, ai_component:, **options)
          validate_options!(options)

          logger.error(message: message,
            klass: self.class.to_s,
            event_name: event_name,
            ai_component: ai_component,
                       **options)
        end

        def log_warn(message:, event_name:, ai_component:, **options)
          validate_options!(options)

          logger.warn(message: message,
            klass: self.class.to_s,
            event_name: event_name,
            ai_component: ai_component,
                       **options)
        end

        def validate_options!(options)
          self.class.validate_options!(options)
        end

        def token_usage_fields(usage)
          return {} unless usage.is_a?(Hash)

          entries = usage.filter_map do |model_name, counts|
            next unless counts.is_a?(Hash)

            { model_name: model_name, input_tokens: counts['input_tokens'], output_tokens: counts['output_tokens'] }
          end

          entries.empty? ? {} : { token_usage: entries }
        end
      end
    end
  end
end
