# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module WorkItemReader
          class Executor < Identifier
            include Concerns::ReaderTooling

            RESOURCE_NAME = 'work item'
            NAME = "WorkItemReader"
            HUMAN_NAME = 'Work Item Search'

            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::WorkItemReader::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::WorkItemReader::Prompts::Anthropic
            }.freeze

            PROJECT_REGEX = {
              'url' => WorkItem.link_reference_pattern,
              'reference' => WorkItem.reference_pattern
            }.freeze

            def unit_primitive
              'work_item_reader'
            end

            private

            def reference_pattern_by_type
              PROJECT_REGEX
            end

            def by_iid(resource_identifier)
              return unless group_from_context || projects_from_context

              work_items = WorkItem.in_projects(projects_from_context).iid_in(resource_identifier.to_i) ||
                WorkItem.in_namespaces(group_from_context).iid_in(resource_identifier.to_i)

              work_items.first if work_items.one?
            end

            def extract_project(text, type)
              return projects_from_context.first unless projects_from_context.blank?

              path = text.match(reference_pattern_by_type[type])&.values_at(:group_or_project_namespace)

              # Epics belong to a group. The `ReferenceExtractor` expects a `project`
              # but does not use it for the extraction of epics. When we cannot find issue with a given path,
              # we assume that it is an epic reference.
              authorized_project = context.current_user.authorized_projects.first

              if path
                context.current_user.authorized_projects.find_by_full_path(path.first) || authorized_project
              else
                authorized_project
              end
            end

            def resource_name
              RESOURCE_NAME
            end

            def get_resources(extractor)
              extractor.work_items
            end
          end
        end
      end
    end
  end
end
