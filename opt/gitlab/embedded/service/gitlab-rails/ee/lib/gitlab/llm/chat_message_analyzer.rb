# frozen_string_literal: true

module Gitlab
  module Llm
    class ChatMessageAnalyzer
      def initialize(messages)
        @messages = messages
        @current_message = messages.last
        @conversation = ::Gitlab::Llm::ChatStorage.last_conversation(messages)
        @attributes = {}
      end

      def execute
        return {} unless current_message

        analyze_conversation!
        analyze_current_message!
        analyze_previous_question!
        analyze_is_first_question_after_reset!
        analyze_url!

        attributes
      end

      private

      attr_reader :messages, :conversation, :attributes, :current_message

      def analyze_conversation!
        attributes.merge!(
          'number_of_conversations' => messages.count(&:conversation_reset?) + 1,
          'number_of_questions_in_conversation' => conversation.count(&:question?),
          'length_of_questions_in_conversation' =>
            conversation.select(&:question?).sum { |m| m.content.size }
        )
      end

      def analyze_current_message!
        attributes.merge!(
          'length_of_questions' => current_message.content.size,
          'time_since_beginning_of_conversation' =>
            (current_message.timestamp - conversation.first.timestamp).to_i
        )
      end

      def analyze_previous_question!
        previous_question = messages[0..-2].reverse_each.find(&:question?)

        return unless previous_question

        attributes['time_since_last_question'] = (current_message.timestamp - previous_question.timestamp).to_i

        return unless current_message.referer_url.present? && previous_question.referer_url.present?

        attributes['asked_on_the_same_page'] = current_message.referer_url == previous_question.referer_url
      end

      def analyze_is_first_question_after_reset!
        attributes['first_question_after_reset'] = (
          messages.size > 1 &&
          messages[-2].conversation_reset? &&
          !current_message.conversation_reset?
        )
      end

      def analyze_url!
        urls = URI.extract(current_message.content, %w[http https])

        attributes["contains_link"] = true if urls.present?

        urls.select! do |url|
          url.start_with?(Gitlab.config.gitlab.base_url)
        end

        urls.each do |url|
          route = Rails.application.routes.recognize_path(url)

          next unless route[:action] == 'show'

          case route[:controller]
          when 'projects/issues'
            attributes["contains_link_to_issue"] = true
          when 'groups/epics'
            attributes["contains_link_to_epic"] = true
          when 'projects/pipelines'
            attributes["contains_link_to_pipeline"] = true
          when 'projects/blob'
            attributes["contains_link_to_code"] = true
          end
        end
      end
    end
  end
end
