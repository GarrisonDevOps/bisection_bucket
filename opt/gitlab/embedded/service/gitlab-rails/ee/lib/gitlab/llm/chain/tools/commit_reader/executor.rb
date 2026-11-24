# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module CommitReader
          class Executor < Identifier
            include Concerns::ReaderTooling

            RESOURCE_NAME = 'commit'
            NAME = "CommitReader"
            HUMAN_NAME = 'Commit Search'

            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::CommitReader::Prompts::Anthropic
            }.freeze

            PROJECT_REGEX = {
              'url' => Commit.link_reference_pattern,
              'reference' => Commit.reference_pattern
            }.freeze

            def unit_primitive
              'commit_reader'
            end

            private

            def reference_pattern_by_type
              PROJECT_REGEX
            end

            def resource_name
              RESOURCE_NAME
            end

            def get_resources(extractor)
              extractor.commits
            end
          end
        end
      end
    end
  end
end
