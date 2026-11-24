# frozen_string_literal: true

module Mcp
  module Tools
    module Security
      class ListVulnerabilitiesService < Base::GraphqlService
        include Availability

        container_arguments project: :project_full_path

        register_version '0.1.0', {
          toolset: :code_security,
          description: 'List security vulnerabilities in a GitLab project. ' \
            'The project must be specified using its project_full_path (e.g., "namespace/project" or ' \
            '"group/subgroup/project"). ' \
            'Supports filtering by severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN), ' \
            'report type (SAST, DAST, DEPENDENCY_SCANNING, etc.), ' \
            'and state (CONFIRMED, DETECTED, DISMISSED, RESOLVED). ' \
            'Returns paginated vulnerability metadata; use get_vulnerability for full details ' \
            'of a single vulnerability. ' \
            'Note: Requires the security_dashboard licensed feature to be enabled.',
          input_schema: {
            type: 'object',
            required: ['project_full_path'],
            properties: {
              project_full_path: {
                type: 'string',
                description: 'Full path of the project (e.g., "namespace/project" or "group/subgroup/project").'
              },
              severity: {
                type: 'array',
                description: 'Filter by severity level. Omit to include vulnerabilities of any severity.',
                items: {
                  type: 'string',
                  enum: %w[CRITICAL HIGH MEDIUM LOW INFO UNKNOWN]
                }
              },
              report_type: {
                type: 'array',
                description: 'Filter by security report type. Omit to include all report types.',
                items: {
                  type: 'string',
                  enum: ::Types::VulnerabilityReportTypeEnum.values.keys
                }
              },
              state: {
                type: 'array',
                description: 'Filter by vulnerability state. Omit to include vulnerabilities in any state.',
                items: {
                  type: 'string',
                  enum: ::Types::VulnerabilityStateEnum.values.keys
                }
              },
              **Mcp::Tools::Concerns::CursorPagination.input_schema_params(items: 'vulnerabilities')
            }
          },
          annotations: {
            title: 'List vulnerabilities',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Security::ListVulnerabilitiesTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end

        override :perform_default
        def perform_default(arguments = {})
          perform_v0_1_0(arguments)
        end
      end
    end
  end
end
