# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module SelfHostedModels
        class IdentifierSuggester
          CUSTOM_OPENAI_PREFIX = 'custom_openai/'
          MODELS_PATH = '/models'
          TIMEOUT = 5.seconds
          MAX_SUGGESTIONS = 5

          def initialize(self_hosted_model)
            @self_hosted_model = self_hosted_model
          end

          def suggestion_message
            return unless suggestable?

            served_ids = available_model_ids
            return if served_ids.blank? || served_ids.include?(configured_id)

            format(
              s_('AdminSelfHostedModels|The provided identifier does not exist. Did you mean %{suggestions}?'),
              suggestions: format_suggestions(served_ids)
            )
          rescue *Gitlab::HTTP::HTTP_ERRORS
            nil
          end

          private

          attr_reader :self_hosted_model

          def suggestable?
            return false if self_hosted_model.nil? || self_hosted_model.endpoint.blank?

            identifier.start_with?(CUSTOM_OPENAI_PREFIX)
          end

          def identifier
            self_hosted_model.identifier.to_s
          end

          def configured_id
            identifier.delete_prefix(CUSTOM_OPENAI_PREFIX)
          end

          def available_model_ids
            response = Gitlab::HTTP.get(
              models_url,
              headers: request_headers,
              allow_local_requests: true,
              timeout: TIMEOUT
            )
            return [] unless response.code == 200

            parse_model_ids(response.body)
          end

          def models_url
            "#{self_hosted_model.endpoint.chomp('/')}#{MODELS_PATH}"
          end

          def parse_model_ids(body)
            data = ::Gitlab::Json.safe_parse(body)&.fetch('data', nil)
            return [] unless data.is_a?(Array)

            data.filter_map { |entry| entry['id'] if entry.is_a?(Hash) }
          end

          def request_headers
            { 'Accept' => 'application/json' }.tap do |headers|
              headers['Authorization'] = "Bearer #{self_hosted_model.api_token}" if self_hosted_model.api_token.present?
            end
          end

          def format_suggestions(served_ids)
            shown = served_ids.first(MAX_SUGGESTIONS).map { |id| "#{CUSTOM_OPENAI_PREFIX}#{id}" }

            remaining = served_ids.size - shown.size
            shown << format(s_('AdminSelfHostedModels|%{count} more'), count: remaining) if remaining > 0

            shown.to_sentence(two_words_connector: ' or ', last_word_connector: ' or ')
          end
        end
      end
    end
  end
end
