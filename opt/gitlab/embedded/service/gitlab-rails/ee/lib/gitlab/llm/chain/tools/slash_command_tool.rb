# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        class SlashCommandTool < Tool
          include Concerns::AiDependent
          include ::Gitlab::InternalEventsTracking
          extend ::Gitlab::Utils::Override

          def perform
            return input_blank_message(command) if input_blank? && !allow_blank_message?

            track_usage_event

            content = request(&streamed_request_handler(StreamedAnswer.new))

            Answer.new(status: :ok, context: context, content: content, tool: nil)
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e)

            Answer.error_answer(
              error: e,
              context: context,
              error_code: "M4000"
            )
          end
          traceable :perform, run_type: 'tool'

          private

          attr_reader :command

          # Tools opt in to Duo usage tracking by naming their internal event.
          def usage_event_name
            nil
          end

          # Placed after the blank-input guard so a not-executed invocation is
          # not counted as usage, and before the request so the event records
          # the request rather than its outcome (mirrors Llm::ChatService).
          def track_usage_event
            return unless usage_event_name

            track_internal_event(usage_event_name, user: context.current_user, project: context.project)
          end

          override :prompt_options
          def prompt_options
            super.merge(command_options).merge(selected_text_options).merge(context_options)
          end

          def context_options
            {}
          end

          # this method is implemented here to force children of this class to re-implement explicitly, using correct
          # service_name, which may be different for every tool
          override :ai_request
          def ai_request
            raise NotImplementedError
          end

          def selected_text_options
            {
              selected_text: context.current_file[:selected_text].to_s,
              file_content: file_content,
              language_info: language_info
            }
          end

          def command_options
            return {} unless command

            command.prompt_options
          end

          def file_content
            content = trimmed_content
            return '' unless content

            partial = content[:is_trimmed] ? 'a part of ' : ''

            <<~TEXT
              Here is #{partial}the content of the file user is working with:
              <file>
                #{content[:content]}
              </file>
            TEXT
          end

          def trimmed_content
            file = context.current_file
            return unless file[:content_above_cursor].present? || file[:content_below_cursor].present?

            max_size = provider_prompt_class::MAX_CHARACTERS / 10
            above = file[:content_above_cursor].to_s.last(max_size)
            below = file[:content_below_cursor].to_s.first(max_size - above.size)
            is_trimmed = above.size < file[:content_above_cursor].to_s.size ||
              below.size < file[:content_below_cursor].to_s.size

            {
              content: "#{above}#{file[:selected_text]}#{below}",
              is_trimmed: is_trimmed
            }
          end

          def filename
            context.current_file[:file_name].to_s
          end

          def language_info
            language = context.language
            return '' unless language.name.present?

            "The code is written in #{language.name} and stored as #{filename}"
          end

          def input_blank?
            return unless command

            command.user_input.blank? && context.current_file[:selected_text].blank?
          end

          def allow_blank_message?
            raise NotImplementedError
          end

          def input_blank_message(command)
            platform = if command.platform_origin == SlashCommand::VS_CODE_EXTENSION
                         'editor'
                       else
                         'browser'
                       end

            content = format(
              s_("AI|Your request does not seem to contain code to %{action}. " \
                "To %{human_name} select the lines of code in your %{platform} " \
                "and then type the command %{command_name} in the chat. " \
                "You may add additional instructions after this command. If you have no code to select, " \
                "you can also simply add the code after the command."),
              action: self.class::ACTION,
              human_name: self.class::HUMAN_NAME.downcase,
              command_name: command.name,
              platform: platform
            )

            Answer.new(status: :not_executed, context: context, content: content, tool: nil)
          end
        end
      end
    end
  end
end
