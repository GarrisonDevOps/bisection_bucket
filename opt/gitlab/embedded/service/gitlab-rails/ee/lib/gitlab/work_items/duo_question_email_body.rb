# frozen_string_literal: true

module Gitlab
  module WorkItems
    # Rewrites the machine-readable question payload the workplan flow attaches to a
    # note into prose, for the notification emails that cannot run the work item UI's
    # parser. The page hides the payload with CSS and re-renders it as an interactive
    # card; email has neither.
    # See https://gitlab.com/gitlab-org/gitlab/-/issues/627212.
    module DuoQuestionEmailBody
      class << self
        def rewrite(note, format: :html)
          body = note.note
          return body unless DuoQuestion.payload_hint?(body)
          return body unless duo_flow_authored?(note)

          rewrite_payloads(body, format)
        end

        private

        # Workflow links are written after notification enqueue, so gate on the committed author.
        # ItemConsumer restricts this to flow service accounts; disabled flows remain eligible
        # so their existing questions stay readable.
        def duo_flow_authored?(note)
          ::Gitlab::SafeRequestStore.fetch([:duo_question_flow_author, note.author_id]) do
            ::Ai::Catalog::ItemConsumer.for_service_account(note.author_id).exists?
          end
        end

        # Remove unrenderable payloads because the preceding prose contains the question.
        def rewrite_payloads(body, format)
          rewritten = DuoQuestion::FENCE_REGEX.replace_gsub(body) do |match|
            prose_for(DuoQuestion.from_fence(match[:payload]), format)
          end
          rewritten = DuoQuestion::MARKER_REGEX.replace_gsub(rewritten) do |match|
            prose_for(DuoQuestion.from_marker(match[:content]), format)
          end

          return body if rewritten == body

          rewritten.rstrip
        end

        def prose_for(payload, format)
          return '' unless renderable?(payload)

          bullets = payload[:options].map { |option| bullet_for(option, format) }

          "#{instruction(payload[:multiple])}\n\n#{bullets.join("\n")}\n"
        end

        def renderable?(payload)
          return false if payload.nil?
          return false if payload[:type] != DuoQuestion::QUESTION_TYPE_CLOSED
          return false if payload[:declared_count] > DuoQuestion::MAX_OPTIONS

          payload[:options].present?
        end

        def instruction(multiple)
          if multiple
            s_('WorkItemDuoQuestion|Choose one or more of these options, or answer in your own words:')
          else
            s_('WorkItemDuoQuestion|Choose one of these options, or answer in your own words:')
          end
        end

        def bullet_for(option, format)
          bullet = "- **#{escape(option[:label], format)}**"
          bullet += " (#{s_('WorkItemDuoQuestion|Recommended')})" if option[:recommended]
          bullet += ": #{escape(option[:description], format)}" if option[:description].present?
          bullet
        end

        # Prevents model-authored option text from becoming active Markdown, but
        # only for the part that is rendered as Markdown. The text part is emitted
        # byte for byte, so escaping there shows the reader backslashes nothing
        # downstream will consume, and there is no Markdown to inject into.
        def escape(text, format)
          return text unless format == :html

          ::GLFMMarkdown.escape_commonmark_inline(text)
        end
      end
    end
  end
end
