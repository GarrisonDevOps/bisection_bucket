# frozen_string_literal: true

module Llm
  class GitCommandService < BaseService
    include Gitlab::Llm::Concerns::AiGatewayClientConcern

    TEMPERATURE = 0.4
    INPUT_CONTENT_LIMIT = 300
    MAX_RESPONSE_TOKENS = 300

    def valid?
      options[:prompt].size < INPUT_CONTENT_LIMIT &&
        Ability.allowed?(user, :access_glab_ask_git_command)
    end

    private

    def ai_action
      :glab_ask_git_command
    end

    def prompt_version
      '1.0.0'
    end

    alias_method :unit_primitive_name, :ai_action
    alias_method :prompt_name, :ai_action

    def inputs
      options
    end

    def perform
      response = perform_ai_gateway_request!(user: user, tracking_context: {})

      response_modifier = ::Gitlab::Llm::AiGateway::ResponseModifiers::GitCommand.new(response)
      Gitlab::Tracking::AiTracking.track_user_activity(user)

      success(response_modifier.response_body)
    end
  end
end
