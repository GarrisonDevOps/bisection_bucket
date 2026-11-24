# frozen_string_literal: true

module SystemNotes
  class VulnerabilitiesService < ::SystemNotes::BaseService
    # Called when state is changed for 'vulnerability'
    # Message is established based on the logic relating to the
    # vulnerability state enum and the current state.
    # If no state transition is present, we assume the vulnerability
    # is newly detected.
    def change_vulnerability_state(body = nil)
      body ||= state_change_body

      create_note(NoteSummary.new(noteable, project, author, body, action: "vulnerability_#{to_state}"))
    end

    class << self
      def formatted_note(transition:, to_value:, reason:, comment:, attribute: "status", from_value: nil)
        format(
          "%{transition} vulnerability %{attribute}%{from_value} to %{to_value}%{reason}%{comment}",
          transition: transition,
          attribute: attribute,
          from_value: formatted_from(from_value),
          to_value: to_value.to_s.titleize,
          comment: formatted_comment(comment),
          reason: formatted_reason(reason, to_value)
        )
      end

      private

      def formatted_reason(reason, to_value)
        return if to_value.to_sym != :dismissed
        return if reason.blank?

        ": #{reason.titleize}"
      end

      def formatted_comment(comment)
        return unless comment.present?

        format(' with the following comment: "%{comment}"', comment: comment)
      end

      def formatted_from(from_value)
        return unless from_value.present?

        format(' from %{from_value}', from_value: from_value.to_s.titleize)
      end
    end

    private

    def state_change_body
      if state_transition.present?
        self.class.formatted_note(
          transition: transition_name,
          from_value: from_state,
          to_value: to_state,
          reason: state_transition.dismissal_reason,
          comment: state_transition.comment
        )
      else
        "changed vulnerability status to Detected"
      end
    end

    def transition_name
      state_transition.to_state_detected? ? 'reverted' : 'changed'
    end

    def from_state
      @from_state ||= state_transition.from_state
    end

    def to_state
      @to_state ||= state_transition&.to_state || 'detected'
    end

    def state_transition
      @state_transition ||= noteable.latest_state_transition
    end
  end
end
