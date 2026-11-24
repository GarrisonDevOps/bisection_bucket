# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Utils
        class Prompt
          def self.as_assistant(*inputs)
            join(:assistant, inputs)
          end

          def self.as_system(*inputs)
            join(:system, inputs)
          end

          def self.as_user(*inputs)
            join(:user, inputs)
          end

          def self.join(role, *inputs)
            [role, inputs.join("\n")]
          end

          def self.no_role_text(prompt_template, input_variables)
            prompt = prompt_template.map(&:last).join("\n")

            format(prompt, input_variables)
          end

          def self.role_text(prompt_template, input_variables, roles: {})
            prompt = prompt_template.map do |template|
              next if template.last.empty?

              role = roles.fetch(template.first.to_s, nil)

              "#{role}#{separator(role)}#{template.last}"
            end.join("\n\n")

            format(prompt, input_variables)
          end

          def self.separator(predecessor)
            return if predecessor.blank?

            ': '
          end

          def self.role_conversation(prompt_template)
            prompt_template.map do |x|
              { role: x.first, content: x.last }
            end
          end

          # only use with pre-defined messages, not user content
          def self.format_conversation(prompt, variables)
            prompt.map do |message|
              [message[0], format(message[1], variables)]
            end
          end
        end
      end
    end
  end
end
