# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class ReviewMergeRequest
          class ResponseBodyParser
            include ::Gitlab::Utils::StrongMemoize

            REVIEW_BLOCK_REGEX = %r{<review>.*?</review>}m
            COMMENT_WRAPPER_REGEX = %r{^<comment (.+?)>(?:\n?)(.+?)</comment>$}m
            COMMENT_ATTR_REGEX = %r{([^\s]*?)="(.*?)"}
            SUMMARY_REGEX = %r{<summary>(.*?)</summary>}m
            COMMENTS_SUMMARY_REGEX = %r{<comments_summary>(.*?)</comments_summary>}m

            class Comment
              ATTRIBUTES = %w[old_line new_line end_line file severity category confidence].freeze
              STRING_ATTRIBUTES = %w[file severity category].freeze

              attr_reader :attributes, :content, :from, :suggestion

              # The XML transport leaves `suggestion` nil; its fence is already part of `content`.
              def initialize(attrs, content, from, suggestion: nil)
                @attributes = attrs
                @content = content
                @from = from
                @suggestion = suggestion
              end

              ATTRIBUTES.each do |attr|
                define_method(attr) do
                  STRING_ATTRIBUTES.include?(attr) ? attributes[attr] : Integer(attributes[attr], exception: false)
                end
              end

              def valid?
                return false if content.blank?
                return false if old_line.blank? && new_line.blank?
                return false if file.blank?

                true
              end
            end

            attr_reader :response

            def initialize(response)
              @response = response
            end

            def comments
              return [] if response.blank?

              review_block = extract_review_block
              return [] if review_block.blank?

              review_block.scan(COMMENT_WRAPPER_REGEX).filter_map do |attrs, body|
                parsed_body = parsed_content(body)
                comment = Comment.new(parsed_attrs(attrs), parsed_body[:body], parsed_body[:from])
                comment if comment.valid?
              end
            end
            strong_memoize_attr :comments

            def no_issues_summary
              extract_tagged_content(SUMMARY_REGEX)
            end
            strong_memoize_attr :no_issues_summary

            def comments_summary
              extract_tagged_content(COMMENTS_SUMMARY_REGEX)
            end
            strong_memoize_attr :comments_summary

            private

            def extract_tagged_content(regex)
              return if response.blank?

              response.match(regex)&.then { |m| m[1]&.strip.presence }
            end

            def extract_review_block
              # Find the last occurrence of <review>...</review> in the response
              # This ensures we get the actual review output, not any examples in thinking steps
              matches = response.scan(REVIEW_BLOCK_REGEX)
              matches.last
            end

            def parsed_attrs(attrs)
              Hash[attrs.scan(COMMENT_ATTR_REGEX)]
            end

            def parsed_content(body)
              ::Gitlab::Llm::Utils::CodeSuggestionFormatter.parse(body)
            end
          end
        end
      end
    end
  end
end
