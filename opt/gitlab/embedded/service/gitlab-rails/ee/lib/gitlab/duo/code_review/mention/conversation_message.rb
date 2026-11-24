# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Mention
        module ConversationMessage
          module_function

          def render(note, max_length: nil)
            author = note.authored_by_duo_bot? ? 'GitLabDuo' : "@#{note.author.username}"
            body = note.note.to_s
            body = body.truncate(max_length) if max_length

            "<message author=\"#{author}\">\n#{CGI.escapeHTML(body)}\n</message>"
          end
        end
      end
    end
  end
end
