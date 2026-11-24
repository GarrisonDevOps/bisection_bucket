# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      class SlashCommand
        VS_CODE_EXTENSION = 'vs_code_extension'
        WEB = 'web'

        # @param [Gitlab::Llm::AiMessage] message
        # @param [Gitlab::Llm::Chain::GitlabContext] context
        # @param [Array] tools
        def self.for(message:, context:, tools: [])
          command, user_input = message.slash_command_and_input
          return unless command

          tool = tools.find do |tool|
            next unless tool::Executor.respond_to?(:slash_commands)

            tool::Executor.slash_commands.has_key?(command)
          end

          return unless tool

          command_options = tool::Executor.slash_commands[command]

          platform_origin = platform_origin(message)
          new(name: command, user_input: user_input, tool: tool, command_options: command_options,
            context: context, platform_origin: platform_origin)
        end

        def self.platform_origin(message)
          if message.platform_origin == VS_CODE_EXTENSION
            VS_CODE_EXTENSION
          else
            WEB
          end
        end

        attr_reader :name, :user_input, :tool, :context, :platform_origin

        def initialize(name:, user_input:, tool:, command_options:, context:, platform_origin: nil)
          @name = name
          @user_input = user_input
          @tool = tool
          @selected_code_without_input_instruction = command_options[:selected_code_without_input_instruction]
          @selected_code_with_input_instruction = command_options[:selected_code_with_input_instruction]
          @input_without_selected_code_instruction = command_options[:input_without_selected_code_instruction]
          @platform_origin = platform_origin
          @context = context
        end

        def prompt_options
          {
            input: instruction
          }
        end

        private

        def instruction
          instruction_template = select_instruction_template
          return formatted_instruction(instruction_template) if instruction_template

          @selected_code_without_input_instruction
        end

        def select_instruction_template
          return if user_input.blank?

          if @context.current_file[:selected_text].nil? && @input_without_selected_code_instruction.present?
            @input_without_selected_code_instruction
          elsif @selected_code_with_input_instruction.present?
            @selected_code_with_input_instruction
          end
        end

        def formatted_instruction(command_instruction)
          format(command_instruction, input: user_input)
        end
      end
    end
  end
end
