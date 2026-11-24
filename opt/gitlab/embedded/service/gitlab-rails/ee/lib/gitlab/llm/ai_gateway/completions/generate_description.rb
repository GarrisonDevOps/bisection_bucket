# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class GenerateDescription < Base
          def inputs
            { content: prompt_message.content, template: template }
          end

          private

          def template
            return if options[:description_template_name].blank? || !resource.is_a?(Issue)

            begin
              TemplateFinder.new(:issues, resource.project, name: options[:description_template_name]).execute&.content
            rescue Gitlab::Template::Finders::RepoTemplateFinder::FileNotFoundError
              nil
            end
          end
        end
      end
    end
  end
end
