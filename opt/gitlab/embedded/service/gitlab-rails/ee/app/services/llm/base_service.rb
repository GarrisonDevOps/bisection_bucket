# frozen_string_literal: true

module Llm
  class BaseService
    include Gitlab::Llm::Concerns::Logger
    include Gitlab::DuoChatResourceHelper

    INVALID_MESSAGE = 'AI features are not enabled or resource is not permitted to be sent.'

    def initialize(user, resource, options = {})
      @user = user
      @resource = resource
      @options = options
    end

    def execute
      unless valid?
        log_info(message: "Returning from Service due to validation",
          event_name: 'permission_denied',
          ai_component: 'abstraction_layer')
        return error(INVALID_MESSAGE)
      end

      result = perform

      result.is_a?(ServiceResponse) ? result : success(ai_message: prompt_message)
    end

    def valid?
      return false if resource && !Gitlab::Llm::Utils::Authorizer.resource(resource: resource, user: user).allowed?

      ai_integration_enabled? && user_can_send_to_ai?
    end

    private

    attr_reader :user, :resource, :options

    def perform
      raise NotImplementedError
    end

    def ai_integration_enabled?
      Gitlab::Llm::Utils::FlagChecker.flag_enabled_for_feature?(ai_action)
    end

    def user_can_send_to_ai?
      user.allowed_to_use?(ai_action)
    end

    def prompt_message
      @prompt_message ||= build_prompt_message
    end

    def ai_action
      options[:ai_action]
    end

    def build_prompt_message(attributes = options)
      action_name = attributes[:ai_action] || ai_action

      message_attributes = {
        request_id: SecureRandom.uuid,
        content: content(action_name),
        role: ::Gitlab::Llm::AiMessage::ROLE_USER,
        ai_action: action_name,
        user: user,
        context: ::Gitlab::Llm::AiMessageContext.new(resource: resource, user_agent: attributes[:user_agent]),
        additional_context: ::Gitlab::Llm::AiMessageAdditionalContext.new(attributes[:additional_context]),
        thread: attributes[:thread]
      }.merge(attributes)
      ::Gitlab::Llm::AiMessage.for(action: action_name).new(message_attributes)
    end

    def content(action_name)
      action_name.to_s.humanize
    end

    def schedule_completion_worker(job_options = options)
      message = prompt_message

      job_options[:start_time] = start_time

      log_conditional_info(
        message.user,
        message: "Enqueuing CompletionWorker",
        event_name: 'worker_enqueued',
        ai_component: 'abstraction_layer',
        namespace: namespace&.root_ancestor,
        user_id: message.user.id,
        resource_id: message.resource&.id,
        resource_class: message.resource&.class&.name,
        request_id: message.request_id,
        action_name: message.ai_action,
        options: job_options
      )

      ::Llm::CompletionWorker.perform_for(message, job_options)
    end

    def success(payload)
      ServiceResponse.success(payload: payload)
    end

    def error(message)
      ServiceResponse.error(message: message)
    end

    def start_time
      ::Gitlab::Metrics::System.monotonic_time
    end
  end
end
