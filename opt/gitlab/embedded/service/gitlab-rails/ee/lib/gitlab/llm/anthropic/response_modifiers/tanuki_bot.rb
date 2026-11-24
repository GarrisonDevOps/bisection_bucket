# frozen_string_literal: true

module Gitlab
  module Llm
    module Anthropic
      module ResponseModifiers
        class TanukiBot < Gitlab::Llm::BaseResponseModifier
          include Gitlab::Utils::StrongMemoize

          CONTENT_ID_FIELD = 'ATTRS'
          CONTENT_ID_REGEX = /CNT-IDX-(?<id>\d+)/
          NO_ANSWER_REGEX = /i do.*n.+know/i

          def initialize(ai_response, current_user, search_documents:)
            @current_user = current_user
            @search_documents = search_documents.map(&:with_indifferent_access)
            super(ai_response)
          end

          def response_body
            parsed_response && parsed_response[:content]
          end

          def extras
            return parsed_response[:extras] if parsed_response

            super
          end

          def errors
            @errors ||= [ai_response&.dig(:error)].compact
          end

          private

          attr_reader :current_user, :search_documents

          def parsed_response
            text = ai_response&.dig(:completion).to_s.strip

            return unless text.present?

            message, source_ids = text.split("#{CONTENT_ID_FIELD}:")
            message.strip!

            sources = if source_ids.blank?
                        []
                      elsif message.match?(NO_ANSWER_REGEX)
                        []
                      else
                        find_sources_with_search_documents(source_ids)
                      end

            {
              content: message,
              extras: {
                sources: sources
              }
            }
          end
          strong_memoize_attr :parsed_response

          def find_sources_with_search_documents(source_ids)
            ids = source_ids.scan(/CNT-IDX-(?<id>[0-9a-z]+)/).flatten
            return [] if ids.empty?

            documents = search_documents.select { |doc| ids.include?(doc[:id]) }
            documents.map! do |doc|
              { source_url: doc[:metadata]['filename'] }.merge(doc[:metadata]).symbolize_keys
            end
            documents.uniq!
            documents
          end
        end
      end
    end
  end
end
