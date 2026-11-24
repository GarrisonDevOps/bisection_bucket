# frozen_string_literal: true

module Mcp
  module Tools
    module Jobs
      class SavePipelineJobService < Base::GraphqlService
        register_version '0.1.0', {
          toolset: :ci,
          description: 'Play a manual CI/CD job in a GitLab project, optionally with variables. ' \
            'Provide url, or project_id and job_id. If both are provided, they must identify the same job. ' \
            'This can trigger deployments. Check the job with get_job before playing it.',
          annotations: {
            title: 'Play job',
            readOnlyHint: false,
            destructiveHint: true,
            idempotentHint: false,
            openWorldHint: true
          },
          input_schema: {
            type: 'object',
            required: [],
            properties: {
              url: {
                type: 'string',
                description: 'Full URL of the manual job to play'
              },
              project_id: {
                type: 'string',
                description: 'ID or full path of the project, for example gitlab-org/gitlab'
              },
              job_id: {
                type: 'integer',
                description: 'ID of the manual job to play'
              },
              variables: {
                type: 'array',
                description: 'CI/CD variables to pass to the manual job.',
                items: {
                  type: 'object',
                  properties: {
                    key: { type: 'string', description: 'Name of the variable.' },
                    value: { type: 'string', description: 'Value of the variable' },
                    variable_type: {
                      type: 'string',
                      enum: ::Ci::Variable.variable_types.keys,
                      description: 'Type of the variable.'
                    }
                  },
                  required: %w[key value]
                }
              }
            }
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Jobs::SavePipelineJobTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end
      end
    end
  end
end
