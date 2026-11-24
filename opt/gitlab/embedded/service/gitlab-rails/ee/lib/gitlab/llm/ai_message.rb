# frozen_string_literal: true

module Gitlab
  module Llm
    class AiMessage
      include ActiveModel::AttributeAssignment

      ROLE_USER = 'user'
      ROLE_ASSISTANT = 'assistant'
      ROLE_SYSTEM = 'system'
      ALLOWED_ROLES = [ROLE_USER, ROLE_ASSISTANT, ROLE_SYSTEM].freeze

      ATTRIBUTES_LIST = [
        :id, :request_id, :content, :role, :timestamp, :errors, :extras,
        :user, :ai_action, :client_subscription_id, :type, :chunk_id, :context,
        :referer_url, :platform_origin, :additional_context,
        :thread
      ].freeze

      SLASH_COMMAND_TOOLS = [
        ::Gitlab::Llm::Chain::Tools::ExplainCode,
        ::Gitlab::Llm::Chain::Tools::WriteTests,
        ::Gitlab::Llm::Chain::Tools::FixCode,
        ::Gitlab::Llm::Chain::Tools::RefactorCode
      ].freeze

      attr_accessor(*ATTRIBUTES_LIST)

      delegate :resource, to: :context
      delegate :user_agent, to: :context

      def self.for(action:)
        if action.to_s == 'chat'
          ChatMessage
        else
          self
        end
      end

      def initialize(attributes = {})
        attributes = attributes.with_indifferent_access.slice(*ATTRIBUTES_LIST)

        raise ArgumentError, "Invalid role '#{attributes['role']}'" unless ALLOWED_ROLES.include?(attributes['role'])
        raise ArgumentError, "User is required" unless attributes['user']

        assign_attributes(attributes)

        @id ||= SecureRandom.uuid
        @timestamp ||= Time.current
        @errors ||= []
        @extras ||= {}
        @additional_context ||= []
      end

      def to_h
        ATTRIBUTES_LIST.index_with do |attr|
          public_send(attr) # rubocop:disable GitlabSecurity/PublicSend -- to avoid duplication with ATTRIBUTES_LIST.
        end.compact.with_indifferent_access
      end

      def save!
        raise NoMethodError, "Can't save regular AiMessage."
      end

      def to_global_id
        ::Gitlab::GlobalId.build(self)
      end

      def size
        content&.size.to_i
      end

      def user?
        role == ROLE_USER
      end

      def assistant?
        role == ROLE_ASSISTANT
      end

      def slash_command?
        content.to_s.match?(%r{\A/\w})
      end

      def slash_command_prompt?
        return false unless slash_command?

        command, _ = slash_command_and_input

        return false unless SLASH_COMMAND_TOOLS.find do |tool|
          tool::Executor.slash_commands.has_key?(command)
        end

        true
      end

      def slash_command_and_input
        return [] unless slash_command?

        content.split(' ', 2)
      end

      def chat?
        false
      end

      def ==(other)
        super || (
          self.class == other.class &&
            !@id.nil? &&
            @id == other.id
        )
      end

      def thread_id
        thread&.id
      end
    end
  end
end
