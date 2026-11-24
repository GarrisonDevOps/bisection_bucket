# frozen_string_literal: true

module MergeRequests
  class DuoCodeReviewChatWorker # rubocop:disable Scalability/IdempotentWorker -- Running worker twice will create duplicate notes
    include ApplicationWorker
    include ::Gitlab::Utils::StrongMemoize
    include Gitlab::InternalEventsTracking

    # Intent values returned by the AI Gateway classifier prompt defined in:
    # https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/tree/main/ai/features/review/classify_code_review_mention_intent/prompts
    INTENT_CODE_REVIEW = 'code_review_request'
    INTENT_ASSISTANT_FLOW = 'assistant_flow'

    feature_category :dap_code_review

    urgency :low
    data_consistency :sticky
    worker_has_external_dependencies!
    deduplicate :until_executed
    sidekiq_options retry: 3

    def perform(note_id)
      note = Note.find_by_id(note_id)

      return unless note
      return unless note.duo_bot_mentioned?

      project = note.project
      duo_code_review_bot = ::Users::Internal.in_organization(project.organization_id).duo_code_review_bot

      track_internal_event('mention_gitlabduo_in_mr_comment', user: note.author, project: note.project)

      intent = classify_intent(note, duo_code_review_bot)

      handler_class_for(intent, note).new(note).execute
    rescue StandardError => error
      Gitlab::ErrorTracking.track_exception(error)

      create_note_on(note, duo_code_review_bot, error_note)
    end

    private

    def classify_intent(note, duo_code_review_bot)
      message_text = note.note.gsub(/@GitLabDuo\b/i, '').strip
      return if message_text.blank?

      options = { message: message_text }

      if Feature.enabled?(:duo_mention_intent_context, note.project)
        options[:intent_context] = ::Gitlab::Duo::CodeReview::Mention::IntentContext
          .new(note, review_bot: duo_code_review_bot)
          .to_h
      end

      prompt_message = ::Gitlab::Llm::AiMessage.for(action: :classify_code_review_mention_intent).new(
        request_id: SecureRandom.uuid,
        ai_action: 'classify_code_review_mention_intent',
        user: note.author,
        content: message_text,
        role: ::Gitlab::Llm::AiMessage::ROLE_USER,
        context: ::Gitlab::Llm::AiMessageContext.new(resource: note.noteable)
      )

      ::Gitlab::Llm::AiGateway::Completions::ClassifyCodeReviewMentionIntent.new(
        prompt_message,
        nil,
        options
      ).execute[:ai_message]&.content&.strip
    rescue StandardError => error
      Gitlab::ErrorTracking.track_exception(error)
      nil
    end

    def handler_class_for(intent, note)
      return ::Ai::DuoWorkflows::CodeReview::Mention::CodeReviewHandler if intent == INTENT_CODE_REVIEW
      return ::Ai::DuoWorkflows::CodeReview::Mention::AssistantFlowHandler if use_assistant_flow?(intent, note)

      ::Ai::DuoWorkflows::CodeReview::Mention::LegacyChatHandler
    end

    def use_assistant_flow?(intent, note)
      intent == INTENT_ASSISTANT_FLOW &&
        ::Gitlab::Duo::CodeReview.dap?(user: note.author, container: note.project)
    end

    def create_note_on(note, duo_code_review_bot, content)
      return if content.blank?

      merge_request = note.noteable

      ::Notes::CreateService.new(
        merge_request.project,
        duo_code_review_bot,
        noteable: merge_request,
        note: content,
        in_reply_to_discussion_id: note.discussion_id,
        type: note.type
      ).execute
    end

    def error_note
      s_("DuoCodeReview|I encountered some problems while responding to your query. Please try again later.")
    end
  end
end
