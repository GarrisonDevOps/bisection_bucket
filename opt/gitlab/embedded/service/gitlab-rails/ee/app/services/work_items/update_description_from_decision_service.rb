# frozen_string_literal: true

module WorkItems
  class UpdateDescriptionFromDecisionService
    MAX_ATTEMPTS = 2
    MIN_LENGTH_RATIO = 0.5
    UNTOUCHED = %r{```.*?```|`[^`\n]*`|https?://\S+}m

    def initialize(decision:, current_user:)
      @decision = decision
      @work_item = decision.work_item
      @current_user = current_user
    end

    def execute
      return ServiceResponse.error(message: 'Not allowed') unless allowed?

      attempts = 0

      begin
        attempts += 1
        # Reloaded so a retry sees the edit that made the previous attempt stale
        work_item.reset
        update_description(work_item.lock_version)
      rescue ActiveRecord::StaleObjectError
        retry if attempts < MAX_ATTEMPTS

        ServiceResponse.error(message: 'Stale work item')
      end
    end

    private

    attr_reader :decision, :work_item, :current_user

    def allowed?
      current_user.present? && Ability.allowed?(current_user, :update_work_item, work_item) &&
        ::Ai::DuoAgentPlatform.available?(user: current_user, container: work_item.resource_parent)
    end

    def update_description(lock_version)
      description = generate_description
      return ServiceResponse.error(message: 'No description generated') if description.blank?
      return ServiceResponse.error(message: 'Generated description is too short') if truncated?(description)

      result = ::WorkItems::UpdateService.new(
        container: work_item.project || work_item.namespace,
        current_user: current_user,
        params: { description: neutralize_new_mentions(description), lock_version: lock_version }
      ).execute(work_item)
      return ServiceResponse.error(message: Array(result[:message]).to_sentence) if result[:status] == :error

      ServiceResponse.success(payload: { description_version: work_item.saved_description_version })
    end

    def generate_description
      prompt_message = ::Gitlab::Llm::AiMessage.new(
        request_id: SecureRandom.uuid,
        ai_action: 'update_description_from_decision',
        user: current_user,
        content: '',
        role: ::Gitlab::Llm::AiMessage::ROLE_USER,
        context: ::Gitlab::Llm::AiMessageContext.new(resource: work_item)
      )

      result = ::Gitlab::Llm::AiGateway::Completions::UpdateDescriptionFromDecision.new(
        prompt_message, nil, inputs
      ).execute

      content = result&.[](:ai_message)&.content
      strip_quick_actions(content.strip) if content.is_a?(String)
    end

    # UpdateService runs quick actions found in the description as the user, so the
    # model output must not carry any. Extracted, not interpreted, as some commands
    # have side effects when interpreted (for example /add_email).
    def strip_quick_actions(description)
      command_definitions = ::QuickActions::InterpretService.command_definitions
      body, = ::Gitlab::QuickActions::Extractor.new(command_definitions).extract_commands(description)

      body
    end

    # A summarized answer such as "...rest unchanged" would silently replace the original
    def truncated?(description)
      description.length < work_item.description.to_s.length * MIN_LENGTH_RATIO
    end

    # Mentions notify people as the user, so the model must not introduce any. They are
    # wrapped in backticks instead of rejecting the output, as `@scope/package` also matches.
    # Code and URLs are skipped so a `@` in them is not changed.
    def neutralize_new_mentions(description)
      pattern = ::User.reference_pattern
      existing = work_item.description.to_s.scan(pattern).flatten

      description.gsub(Regexp.union(UNTOUCHED, pattern)) do |match|
        username = Regexp.last_match[:user]
        username.nil? || existing.include?(username) ? match : "`#{match}`"
      end
    end

    def inputs
      selected = decision.options.select(&:selected)

      {
        title: work_item.title,
        description: work_item.description.to_s,
        question: decision.title,
        options: decision.options.map(&:content),
        answer: selected.map(&:content).join(', '),
        rationale: decision.resolution_rationale
      }
    end
  end
end
