# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        class Identifier < Tool
          include Concerns::AiDependent
          extend ::Gitlab::Utils::Override

          attr_accessor :retries

          MAX_RETRIES = 3
          PROMPT_VERSION = '^1.0.0'

          def initialize(context:, options:, stream_response_handler: nil)
            super
            @retries = 0
          end

          def perform(&_block)
            MAX_RETRIES.times do
              json = extract_json(request)
              resource = identify_resource(json[:ResourceIdentifierType], json[:ResourceIdentifier])

              # if resource not found then return an error as the answer.
              authorizer = Utils::ChatAuthorizer.resource(
                resource: resource,
                user: context.current_user,
                context: context)

              unless authorizer.allowed?
                log_error(message: "Error finding #{resource_name}",
                  event_name: 'incorrect_response_received',
                  ai_component: 'duo_chat',
                  error_message: authorizer.message)
                return error_with_message(authorizer.message, error_code: "M3003", source: "identifier")
              end

              # now the resource in context is being referenced in user input.
              context.resource = resource

              content = passed_content(json)

              log_conditional_info(context.current_user,
                message: "Answer received from LLM",
                event_name: 'response_received',
                ai_component: 'duo_chat',
                response_from_llm: content)

              return Answer.new(status: :ok, context: context, content: content, tool: nil)
            rescue JSON::ParserError
              error_message = "\nObservation: JSON has an invalid format. Please retry"
              log_error(message: "Json parsing error",
                event_name: 'error',
                ai_component: 'duo_chat')

              options[:suggestions] += error_message
            rescue StandardError => e
              Gitlab::ErrorTracking.track_exception(e)

              return Answer.error_answer(
                error: e,
                context: context,
                error_code: "M4001"
              )
            end

            not_found
          end
          traceable :perform, run_type: 'tool'

          private

          def resource_name
            raise NotImplementedError
          end

          def get_resources(extractor)
            raise NotImplementedError
          end

          def reference_pattern_by_type
            raise NotImplementedError
          end

          def by_iid
            raise NotImplementedError
          end

          def authorize
            Utils::ChatAuthorizer.user(user: context.current_user).allowed?
          end

          def identify_resource(resource_identifier_type, resource_identifier)
            return context.resource if current_resource?(resource_identifier_type, resource_name)

            case resource_identifier_type
            when 'iid'
              by_iid(resource_identifier)
            when 'url', 'reference'
              extract_resource(resource_identifier, resource_identifier_type)
            end
          end
          traceable :identify_resource, name: 'Identify resource', run_type: 'parser'

          def extract_json(response)
            unless response.include?("ResourceIdentifierType")
              response = "```json
                    \{
                      \"ResourceIdentifierType\": \"" + response
            end

            response = (Utils::TextProcessing.text_before_stop_word(response, /Question:/) || response).to_s.strip
            content_after_ticks = response.split(/```json/, 2).last
            content_between_ticks = content_after_ticks&.split(/```/, 2)&.first

            Gitlab::Json::SafeParser.parse(content_between_ticks&.strip.to_s).with_indifferent_access
          end

          def already_used_answer
            resource = context.resource
            content = "You already have identified the #{resource_name} #{resource.to_global_id}, read carefully."
            log_conditional_info(context.current_user,
              message: "Resource already identified",
              event_name: 'incorrect_response_received',
              ai_component: 'duo_chat',
              error_message: content)

            ::Gitlab::Llm::Chain::Answer.new(
              status: :not_executed, context: context, content: content, tool: nil, is_final: false
            )
          end

          def extract_resource(text, type)
            project = extract_project(text, type)
            return unless project

            extractor = Gitlab::ReferenceExtractor.new(project, context.current_user)
            extractor.analyze(text, {})
            resources = get_resources(extractor)

            resources.first if resources.one?
          end

          def extract_project(text, type)
            return projects_from_context.first unless projects_from_context.blank?

            project_path = text.match(reference_pattern_by_type[type])&.values_at(:namespace, :project)
            context.current_user.authorized_projects.find_by_full_path(project_path.join('/')) if project_path
          end

          override :prompt_version
          def prompt_version
            PROMPT_VERSION
          end
        end
      end
    end
  end
end
