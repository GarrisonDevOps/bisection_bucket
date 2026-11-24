# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module BuildReader
          class Executor < Identifier
            include Concerns::ReaderTooling

            RESOURCE_NAME = 'ci build'
            NAME = "BuildReader"
            HUMAN_NAME = 'Build Search'

            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::BuildReader::Prompts::Anthropic
            }.freeze

            def unit_primitive
              'build_reader'
            end

            private

            def extract_resource(text, type)
              return unless type == 'url'

              build_id = text.split('/').last
              ::Ci::Build.find(build_id)
            end

            def resource_name
              RESOURCE_NAME
            end
          end
        end
      end
    end
  end
end
