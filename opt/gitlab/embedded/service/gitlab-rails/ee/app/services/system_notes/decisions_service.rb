# frozen_string_literal: true

module SystemNotes # rubocop:disable Gitlab/BoundedContexts -- SystemNotes module already exists and holds the other services
  class DecisionsService < ::SystemNotes::BaseService
    # Called when a decision is recorded as resolved, whether it was created
    # already resolved or resolved later
    def decision_recorded(decision)
      label = link_label(decision_text(decision))
      body = "recorded a decision [#{label}](#{::Gitlab::UrlBuilder.build(decision)})"

      create_note(NoteSummary.new(noteable, project, author, body, action: 'decision_recorded'))
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, decision_id: decision.id)
    end

    private

    def decision_text(decision)
      decision.options.select(&:selected).map(&:content).join(', ').presence || decision.title.to_s
    end

    def link_label(text)
      ::GLFMMarkdown.escape_commonmark_inline(text.squish)
    end
  end
end
