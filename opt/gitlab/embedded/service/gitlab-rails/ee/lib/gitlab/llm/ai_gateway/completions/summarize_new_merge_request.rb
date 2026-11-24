# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class SummarizeNewMergeRequest < Base
          extend ::Gitlab::Utils::Override
          include Gitlab::Utils::StrongMemoize

          CHARACTER_LIMIT = 2000

          override :inputs
          def inputs
            { extracted_diff: extracted_diff }
          end

          override :root_namespace
          def root_namespace
            resource.try(:root_ancestor)
          end

          private

          def extracted_diff
            Gitlab::Llm::Utils::MergeRequestTool.extract_diff(
              source_project: source_project,
              source_branch: options[:source_branch],
              target_project: resource,
              target_branch: options[:target_branch],
              character_limit: CHARACTER_LIMIT
            )
          end
          strong_memoize_attr :extracted_diff

          override :valid?
          def valid?
            super && extracted_diff.present?
          end

          override :prompt_version
          def prompt_version
            '^2.0.0'
          end

          def source_project
            return resource unless options[:source_project_id]

            source_project = Project.find_by_id(options[:source_project_id])

            if source_project.present? && Ability.allowed?(user, :create_merge_request_from, source_project)
              return source_project
            end

            resource
          end
        end
      end
    end
  end
end
