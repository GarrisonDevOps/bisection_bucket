# frozen_string_literal: true

module CodeSuggestions
  module Prompts
    module CodeGeneration
      class AiGatewayMessages < CodeSuggestions::Prompts::Base
        include Gitlab::Llm::Chain::Concerns::XrayContext

        PROMPT_COMPONENT_TYPE = 'code_editor_generation'
        PROMPT_ID = 'code_suggestions/generations'

        # response time grows with prompt size, so we don't use upper limit size of prompt window
        MAX_INPUT_CHARS = 50000

        def request_params
          {
            prompt_components: [
              {
                type: PROMPT_COMPONENT_TYPE,
                payload: {
                  file_name: file_name,
                  content_above_cursor: content_above_cursor,
                  content_below_cursor: content_below_cursor,
                  language_identifier: language.name,
                  stream: params.fetch(:stream, false),
                  prompt_enhancer: code_generation_enhancer,
                  **prompt_info
                }
              }
            ],
            **model_metadata
          }
        end

        private

        def prompt_info
          prompt_version =
            if model_metadata.present?
              '^1.0.0'
            elsif Feature.enabled?(:incident_fail_over_generation_provider, current_user)
              # vertex + claude_3_5_sonnet_20240620
              '2.0.0'
            else
              # anthropic + claude-sonnet-4-20250514
              '^1.0.0'
            end

          {
            prompt_id: PROMPT_ID,
            prompt_version: prompt_version
          }
        end

        def code_generation_enhancer
          # the fields here are used in AIGW to populate prompt template
          # updating the key names here will break the template rendering
          # please reach out to @code-creation-team in case of updating the hash
          {
            **examples_section_params,
            **existing_code_block_params,
            **context_block_params,
            **libraries_block_params,
            **user_instruction_params
          }
        end

        def examples_section_params
          {
            # TODO: we can migrate all examples to AIGW as followup,
            # eg: CODE_GENERATIONS_EXAMPLES_URI = 'ee/lib/code_suggestions/prompts/code_generation/examples.yml'
            examples_array: language.generation_examples(type: params[:instruction]&.trigger_type)
          }
        end

        def existing_code_block_params
          trimmed_content_above_cursor = content_above_cursor.to_s.last(MAX_INPUT_CHARS)
          trimmed_content_below_cursor = content_below_cursor.to_s.first(MAX_INPUT_CHARS -
           trimmed_content_above_cursor.size)

          {
            trimmed_content_above_cursor: trimmed_content_above_cursor,
            trimmed_content_below_cursor: trimmed_content_below_cursor
          }
        end

        def context_block_params
          related_files = []
          related_snippets = []

          params[:context]&.each do |context|
            if context[:type] == ::Ai::AdditionalContext::CODE_SUGGESTIONS_CONTEXT_TYPES[:file]
              related_files << <<~FILE_CONTENT
              <file_content file_name="#{context[:name]}">
              #{context[:content]}
              </file_content>
              FILE_CONTENT
            elsif context[:type] == ::Ai::AdditionalContext::CODE_SUGGESTIONS_CONTEXT_TYPES[:snippet]
              related_snippets << <<~SNIPPET_CONTENT
              <snippet_content name="#{context[:name]}">
              #{context[:content]}
              </snippet_content>
              SNIPPET_CONTENT
            end
          end

          {
            related_files: related_files,
            related_snippets: related_snippets
          }
        end

        def libraries_block_params
          if libraries.any?
            Gitlab::InternalEvents.track_event(
              'include_repository_xray_data_into_code_generation_prompt',
              project: project,
              namespace: project&.namespace,
              user: params[:current_user]
            )
          end

          { libraries: libraries }
        end

        def user_instruction_params
          instruction = params[:instruction]&.instruction.presence ||
            'Generate the best possible code based on instructions.'

          { user_instruction: instruction }
        end

        def model_metadata
          params = ::Gitlab::Llm::AiGateway::ModelMetadata.new(feature_setting: feature_setting).to_params

          return { model_metadata: params } if params && use_model_metadata?

          {}
        end

        def project
          params[:project]
        end

        # rubocop:disable Gitlab/NoCodeCoverageComment -- covered, read comment below
        # simplecov:disable undercoverage spec keeps failing here but this method is covered with tests
        # in ee/spec/lib/code_suggestions/prompts/code_generation/ai_gateway_messages_spec.rb
        # Through shared examples
        def use_model_metadata?
          return true if ::Ai::AmazonQ.connected?

          return false if feature_setting.nil?

          return true if feature_setting.self_hosted?
          return true if feature_setting.try(:offered_model_ref).present?

          # we only need to return an empty feature setting if those FFs are enabled
          return false if Feature.enabled?(:incident_fail_over_generation_provider, current_user)

          true
        end
        # simplecov:enable
        # rubocop:enable Gitlab/NoCodeCoverageComment
      end
    end
  end
end
