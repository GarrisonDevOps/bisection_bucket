# frozen_string_literal: true

module Gitlab
  module WorkItems
    # Parses the machine-readable question payload the workplan flow attaches to a
    # note, mirroring ee/app/assets/javascripts/work_items/utils/duo_question.js.
    module DuoQuestion
      # RE2 rather than Ruby regexes: a note body is untrusted input, and these
      # lazy quantifiers backtrack quadratically on a body full of unclosed
      # fences. RE2 has no backtracking, so no replacement limit is needed.
      #
      # Stricter than FENCE_RE and MARKER_RE in duo_question.js: these scan a
      # whole body rather than one already-isolated note, so both are anchored.
      FENCE_REGEX = ::Gitlab::UntrustedRegexp.new(
        '(?s)^ {0,3}```json:duo-question[^\n]*\n(?P<payload>.*?)^ {0,3}```[ \t]*(?:\n|\z)',
        multiline: true
      ).freeze
      MARKER_REGEX = ::Gitlab::UntrustedRegexp.new(
        '(?s)^ {0,3}<!--\s*duo:options\s*(?P<content>.*?)-->[ \t]*(?:\n|\z)',
        multiline: true
      ).freeze
      MARKER_ARRAY_REGEX = ::Gitlab::UntrustedRegexp.new('(?s)(?P<array>\[.*?\])').freeze

      # Left as Ruby regexes: neither can backtrack, and both run on the small
      # slice a marker match already bounded.
      MARKER_RECOMMENDED_REGEX = /duo:recommended\s*(?<index>\d+)/
      MARKER_MULTIPLE_REGEX = /duo:multiple\b/

      # Cheap enough to run on every note, and skips the regexes for the
      # overwhelming majority of bodies that carry no payload at all.
      PAYLOAD_HINTS = ['json:duo-question', 'duo:options'].freeze

      QUESTION_TYPE_CLOSED = 'closed'

      # Kept in step with MAX_OPTIONS in duo_question.js, and applied to the
      # options as written rather than the ones that survive validation, because
      # that is where the work item UI applies it.
      MAX_OPTIONS = 5

      # Mirror the work item UI's option validation.
      MAX_LABEL_LENGTH = 200
      MAX_DESCRIPTION_LENGTH = 500

      class << self
        # @param body [String] raw note body
        # @return [Boolean] whether the body may carry a payload, without running the regexes
        def payload_hint?(body)
          PAYLOAD_HINTS.any? { |hint| body.to_s.include?(hint) }
        end

        # The first payload in a body, preferring the fenced form like the work item UI does.
        #
        # @param body [String] raw note body
        # @return [Hash, nil] the parsed payload, or nil when the body carries none
        def parse(body)
          return unless payload_hint?(body)

          fence = FENCE_REGEX.match(body)
          return from_fence(fence[:payload]) if fence

          marker = MARKER_REGEX.match(body)
          from_marker(marker[:content]) if marker
        end

        # @param body [String] raw note body
        # @return [String] the body with every payload removed
        def strip_payloads(body)
          stripped = FENCE_REGEX.replace_gsub(body) { '' }

          MARKER_REGEX.replace_gsub(stripped) { '' }.strip
        end

        # @param raw [String] contents of a fenced payload block
        # @return [Hash, nil] the parsed payload, or nil when it isn't a JSON object
        def from_fence(raw)
          payload = parse_json(raw)
          return unless payload.is_a?(Hash)

          options = payload['options'].is_a?(Array) ? payload['options'] : []

          {
            type: payload['type'],
            question: payload['question'].is_a?(String) ? payload['question'].squish.presence : nil,
            multiple: payload['multiple'] == true,
            declared_count: options.size,
            options: options.filter_map { |option| normalize_option(option) }
          }
        end

        # The marker form carries bare labels and no question, and `duo:recommended`
        # is a 1-based index into the labels rather than a flag on the option itself.
        #
        # @param content [String] contents of an HTML comment marker
        # @return [Hash, nil] the parsed payload, or nil when it has no label array
        def from_marker(content)
          labels = parse_json(MARKER_ARRAY_REGEX.match(content)&.[](:array))
          return unless labels.is_a?(Array)

          recommended = content[MARKER_RECOMMENDED_REGEX, :index].to_i

          {
            type: QUESTION_TYPE_CLOSED,
            question: nil,
            multiple: MARKER_MULTIPLE_REGEX.match?(content),
            declared_count: labels.size,
            options: labels.each_with_index.filter_map do |label, index|
              normalize_option({ 'label' => label, 'recommended' => index + 1 == recommended })
            end
          }
        end

        private

        def parse_json(raw)
          ::Gitlab::Json::SafeParser.parse(raw.to_s)
        rescue ::JSON::ParserError
          nil
        end

        def normalize_option(option)
          return unless option.is_a?(Hash)

          label = option['label']
          return unless label.is_a?(String) && label.present?

          return if label.match?(/[\r\n]/)
          return if label.length > MAX_LABEL_LENGTH

          {
            label: label.squish,
            description: normalize_description(option['description']),
            recommended: option['recommended'] == true
          }
        end

        def normalize_description(description)
          return unless description.is_a?(String)

          description.squish.presence&.slice(0, MAX_DESCRIPTION_LENGTH)
        end
      end
    end
  end
end
