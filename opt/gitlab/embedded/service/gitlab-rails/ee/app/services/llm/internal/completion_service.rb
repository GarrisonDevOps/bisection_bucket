# frozen_string_literal: true

module Llm
  module Internal
    class CompletionService < ::Llm::BaseService
      extend ::Gitlab::Utils::Override

      MAX_RUN_TIME = 30.seconds

      attr_reader :prompt_message, :options

      def initialize(prompt_message, options = {})
        @prompt_message = prompt_message
        @options = options
      end

      def execute
        return unless ai_action_enabled?(prompt_message)

        set_current_context_for_ai_gateway

        with_tracking(prompt_message.ai_action) do
          unless resource_authorized?(prompt_message)
            log_info(message: "Nullifying resource to prevent unauthorized access",
              event_name: 'permission_denied',
              ai_component: 'abstraction_layer',
              user_id: prompt_message.user.to_gid,
              resource_id: prompt_message.resource&.to_gid,
              action_name: prompt_message.ai_action.to_sym,
              request_id: prompt_message.request_id,
              client_subscription_id: prompt_message.client_subscription_id
            )

            prompt_message.context.assign_attributes(resource: nil)
          end

          options.symbolize_keys!
          options[:extra_resource] = ::Llm::ExtraResourceFinder
            .new(prompt_message.user, options.delete(:referer_url)).execute

          completion = ::Gitlab::Llm::CompletionsFactory.completion!(prompt_message, options)
          log_perform(prompt_message, completion.class.name)

          completion.execute
        end
      rescue StandardError => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          e, { user_id: prompt_message.user&.id, resource: prompt_message.resource&.to_gid }
        )
        nil
      end

      private

      def set_current_context_for_ai_gateway
        Gitlab::AiGateway.current_context[:x_gitlab_client_type] = options['x_gitlab_client_type']
        Gitlab::AiGateway.current_context[:x_gitlab_client_version] = options['x_gitlab_client_version']
        Gitlab::AiGateway.current_context[:x_gitlab_client_name] = options['x_gitlab_client_name']
        Gitlab::AiGateway.current_context[:x_gitlab_interface] = options['x_gitlab_interface']
        Gitlab::AiGateway.current_context[:x_gitlab_tracking_context] = options['x_gitlab_tracking_context']
      end

      def with_tracking(ai_action)
        start_time = options[:start_time] || ::Gitlab::Metrics::System.monotonic_time

        response = yield

        update_error_rate(ai_action, response)
        update_duration_metric(ai_action, ::Gitlab::Metrics::System.monotonic_time - start_time)

        response
      rescue StandardError => err
        update_error_rate(ai_action)
        raise err
      end

      def log_perform(prompt_message, completion_class_name)
        log_debug(
          message: "Performing CompletionService",
          event_name: 'completion_service_performed',
          ai_component: 'abstraction_layer',
          user_id: prompt_message.user.to_gid,
          resource_id: prompt_message.resource&.to_gid,
          action_name: prompt_message.ai_action.to_sym,
          request_id: prompt_message.request_id,
          client_subscription_id: prompt_message.client_subscription_id,
          completion_service_name: completion_class_name
        )
      end

      def resource_authorized?(prompt_message)
        !prompt_message.resource ||
          Ability.allowed?(
            prompt_message.user,
            "read_#{prompt_message.resource.to_ability_name}",
            prompt_message.resource
          )
      end

      def update_error_rate(ai_action_name, response = nil)
        completion = ::Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST[ai_action_name.to_sym]
        return unless completion

        result  = response.is_a?(Hash) ? response[:ai_message] : response
        success = result.try(:errors)&.empty?

        Gitlab::Metrics::Sli::ErrorRate[:llm_completion].increment(
          labels: {
            feature_category: completion[:feature_category],
            service_class: completion[:service_class].name
          },
          error: !success
        )
      end

      def update_duration_metric(ai_action_name, duration)
        completion = ::Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST[ai_action_name.to_sym]
        return unless completion

        labels = {
          feature_category: completion[:feature_category],
          service_class: completion[:service_class].name
        }
        Gitlab::Metrics::Sli::Apdex[:llm_completion].increment(
          labels: labels,
          success: duration <= MAX_RUN_TIME
        )
      end

      def ai_action_enabled?(prompt_message)
        Gitlab::Llm::Utils::FlagChecker.flag_enabled_for_feature?(prompt_message.ai_action.to_sym)
      end
    end
  end
end
