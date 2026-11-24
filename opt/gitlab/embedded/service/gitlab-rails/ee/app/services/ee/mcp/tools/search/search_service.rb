# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Search
        module SearchService
          extend ::Gitlab::Utils::Override
          include ::Gitlab::ResourceLookup

          override :transform_arguments
          def transform_arguments(args)
            transformed = super
            apply_context_exclusion(transformed)
          end

          private

          override :properties
          def properties
            properties = super
            if exact_code_search_enabled?
              desc = 'Performs a regex code search. Available for blobs scope; other scopes are ignored.'
              properties[:regex] = { type: 'boolean', description: desc }
            end

            if advanced_search_enabled?
              fields_description = <<~DESC.strip
                Specify which fields to search within. Currently supported:
                - Allowed values: title only
                - Applicable scopes: work_items, merge_requests
              DESC

              properties[:fields] = { type: 'array', items: { type: 'string' }, description: fields_description }
            end

            type_description = <<~DESC.strip
              Filter work items by type. Only applies to work_items scope.
              Available types: issue, task, epic, incident, test_case, requirement, objective, key_result, ticket
            DESC

            properties[:type] = { type: 'array', items: { type: 'string' }, description: type_description }

            properties
          end

          override :description_parts
          def description_parts
            parts = super
            parts << "- Advanced: \"bug AND critical\", \"display | banner\", \"#23456\"" if advanced_search_enabled?
            parts << "- Exact code: \"class User\", \"foo lang:ruby\", \"sym:initialize\"" if exact_code_search_enabled?
            parts
          end

          override :search_capabilities
          def search_capabilities
            capabilities = super
            capabilities << 'advanced (boolean operators)' if advanced_search_enabled?
            capabilities << 'exact code (exact match, regex, symbols)' if exact_code_search_enabled?
            capabilities
          end

          def apply_context_exclusion(args)
            # Only apply exclusion for blobs and wiki_blobs scopes
            return args unless %w[blobs wiki_blobs].include?(args[:scope])

            project = lookup_project(args[:id])
            return args unless project

            exclusion_rules = load_exclusion_rules(project)
            return args if exclusion_rules.empty?

            # Append -filename: or -path: filters to search query
            # Use -path: for patterns with '/', -filename: for simple filenames
            exclusion_filters = exclusion_rules.map do |pattern|
              filter_type = pattern.include?('/') ? 'path' : 'filename'
              "-#{filter_type}:#{pattern}"
            end.join(' ')
            args[:search] = "#{args[:search]} #{exclusion_filters}".strip

            args
          end

          def load_exclusion_rules(project)
            settings = project.project_setting&.duo_context_exclusion_settings

            Hash(settings).fetch('exclusion_rules', [])
          end

          def advanced_search_enabled?
            ::Gitlab::CurrentSettings.elasticsearch_search?
          end

          def exact_code_search_enabled?
            ::Search::Zoekt.search_enabled?
          end
        end
      end
    end
  end
end
