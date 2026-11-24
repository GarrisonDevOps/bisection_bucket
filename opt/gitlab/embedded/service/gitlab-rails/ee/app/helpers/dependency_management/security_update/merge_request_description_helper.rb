# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    module MergeRequestDescriptionHelper
      # Our fence is (longest run + 1), and the Markdown renderer won't treat a fence
      # longer than ~80 backticks as a code span - it emits the backticks as text and
      # parses the rest as Markdown. Cap runs to a small number rather than track the
      # renderer's exact limit (which can change on upgrade); real titles have only a
      # few backticks, so shortening longer runs is safe.
      MAX_BACKTICK_RUN = 10

      # Wraps untrusted text (the advisory title) in an inline code span so it
      # renders literally. Code spans are the one place GitLab runs no Markdown,
      # HTML, or reference (@mention, #issue, link) processing, so nothing in the
      # title can become an attack. Whitespace is collapsed, over-long backtick
      # runs are capped, and the fence is widened past the longest remaining run
      # so a newline or stray backticks can't break out.
      def code_span(text)
        text = text.gsub(/\s+/, ' ').strip
        text = text.gsub(/`{#{MAX_BACKTICK_RUN + 1},}/) { '`' * MAX_BACKTICK_RUN }
        longest_run = text.scan(/`+/).map(&:length).max.to_i
        fence = '`' * (longest_run + 1)
        pad = text.start_with?('`') || text.end_with?('`') ? ' ' : ''

        "#{fence}#{pad}#{text}#{pad}#{fence}"
      end
    end
  end
end
