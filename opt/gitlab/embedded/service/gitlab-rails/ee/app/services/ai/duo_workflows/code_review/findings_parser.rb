# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      # Parses the JSON findings document posted by the Lite and Standard code review flows
      # into Comment objects. Comment is borrowed from the classic ResponseBodyParser.
      class FindingsParser
        include ::Gitlab::Utils::StrongMemoize

        Error = Class.new(StandardError)

        Comment = ::Gitlab::Llm::AiGateway::Completions::ReviewMergeRequest::ResponseBodyParser::Comment

        def initialize(review_output)
          @review_output = review_output
        end

        def comments
          findings.filter_map do |finding|
            next unless finding.is_a?(Hash)

            attributes = finding.slice(*Comment::ATTRIBUTES)
            comment = Comment.new(
              attributes, finding['message'].to_s, finding['target_code'], suggestion: suggestion_for(finding)
            )
            comment if comment.valid?
          end
        end
        strong_memoize_attr :comments

        def comments_summary
          comments.any? ? summary : previous_findings
        end

        def no_issues_summary
          summary if comments.empty? && previous_findings.blank?
        end

        private

        attr_reader :review_output

        def payload
          parsed = ::Gitlab::Json::SafeParser.parse(review_output)
          raise Error, 'review output must be a JSON object' unless parsed.is_a?(Hash)

          parsed
        rescue JSON::ParserError => e
          raise Error, "review output is not valid JSON: #{e.message}"
        end
        strong_memoize_attr :payload

        def findings
          findings = payload['findings']
          raise Error, 'review output must contain a findings array' unless findings.is_a?(Array)

          findings
        end

        def summary
          payload['summary'].to_s.strip.presence
        end

        # Sent only on a re-review that left no new comments but found earlier threads still open.
        def previous_findings
          payload['previous_findings'].to_s.strip.presence
        end

        def suggestion_for(finding)
          from = finding['target_code'].to_s
          to = finding['suggestion']
          return if to.nil? || from.empty? || from == to

          to
        end
      end
    end
  end
end
