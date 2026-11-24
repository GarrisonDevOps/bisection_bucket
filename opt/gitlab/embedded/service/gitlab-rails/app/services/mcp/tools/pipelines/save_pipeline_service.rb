# frozen_string_literal: true

module Mcp
  module Tools
    module Pipelines
      class SavePipelineService < Base::GraphqlService
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::UrlParser

        PARENT_PARAMS = %i[url project_id].freeze

        container_arguments record: { pipeline_id: ->(id) { ::Ci::Pipeline.find_by_id(id)&.project } }

        register_version '0.1.0', {
          toolset: :ci,
          description: 'Run, retry, cancel, or rename a CI/CD pipeline in a GitLab project. ' \
            'Omit pipeline_id and pass ref to run a new pipeline, or pass merge_request_iid to ' \
            'create a pipeline linked to a merge request. Identify the project with exactly one ' \
            'of url or project_id. Pass pipeline_id with action to retry, cancel, or update an ' \
            'existing pipeline; update renames it and requires name.',
          annotations: {
            title: 'Run or update pipeline',
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
                description: 'GitLab URL of the project. Used only when creating a pipeline.'
              },
              project_id: {
                type: 'string',
                description: 'ID or full path of the project. Used only when creating a pipeline.'
              },
              merge_request_iid: {
                type: 'integer',
                description: 'Internal ID of a merge request in the project to create a pipeline for. ' \
                  'When set, creates a pipeline linked to the merge request.'
              },
              pipeline_id: {
                type: 'integer',
                description: 'ID of an existing pipeline to target. When set, requires action. ' \
                  'Omit to create a new pipeline.'
              },
              action: {
                type: 'string',
                enum: Mcp::Tools::Pipelines::SavePipelineTool::ACTIONS,
                description: 'Lifecycle action to perform on pipeline_id. Required when pipeline_id is set.'
              },
              ref: {
                type: 'string',
                description: 'Branch or tag name. Required to create a pipeline on a branch or tag ' \
                  '(when pipeline_id and merge_request_iid are absent).'
              },
              name: {
                type: 'string',
                description: 'New pipeline name. Required for action: "update".'
              },
              variables: {
                type: 'array',
                description: 'Pipeline variables to create the pipeline with.',
                items: {
                  type: 'object',
                  properties: {
                    key: { type: 'string', description: 'Name of the variable.' },
                    value: { type: 'string', description: 'Value of the variable.' },
                    variable_type: {
                      type: 'string',
                      enum: %w[env_var file],
                      description: 'Type of the variable.'
                    }
                  },
                  required: %w[key value]
                }
              },
              inputs: {
                type: 'object',
                description: 'Pipeline input parameters as key-value pairs.'
              }
            }
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Pipelines::SavePipelineTool
        end

        def perform_v0_1_0(arguments)
          if arguments[:merge_request_iid].present?
            %i[pipeline_id ref action name variables inputs].each do |incompatible_param|
              if arguments[incompatible_param].present?
                raise ArgumentError, "Cannot combine merge_request_iid with #{incompatible_param}"
              end
            end

            return perform_create_for_merge_request(arguments)
          end

          # update has no GraphQL mutation, so it dispatches to the metadata
          # service here and must never reach SavePipelineTool's OPERATIONS.
          return perform_update(arguments) if arguments[:action].to_s == 'update'

          execute_graphql_tool(arguments)
        end

        override :perform_default
        def perform_default(arguments = {})
          perform_v0_1_0(arguments)
        end

        private

        def perform_create_for_merge_request(arguments)
          project = resolve_project(arguments)

          message = 'Merge request not found or inaccessible.'
          merge_request = project.merge_requests.find_by_iid(arguments[:merge_request_iid])

          unless merge_request && Ability.allowed?(current_user, :read_merge_request, merge_request)
            return ::Mcp::Tools::Base::Response.error(
              message, reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND
            )
          end

          authorize_granular_token!(project, [:create_merge_request_pipeline], not_found_message: message)

          if merge_request.has_no_commits?
            return ::Mcp::Tools::Base::Response.error(
              'Cannot create a pipeline for this merge request: no commits to build.',
              reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST
            )
          end

          create_pipeline_service = ::MergeRequests::CreatePipelineService.new(
            project: project, current_user: current_user, params: { allow_duplicate: true }
          )

          unless create_pipeline_service.allowed?(merge_request)
            return ::Mcp::Tools::Base::Response.error(
              'Insufficient permissions to create pipeline',
              reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
            )
          end

          response = create_pipeline_service.execute(merge_request)

          pipeline = response.payload
          if pipeline.blank?
            return ::Mcp::Tools::Base::Response.error(
              response.message.presence || 'Pipeline creation failed',
              reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST
            )
          end

          if pipeline.persisted?
            pipeline_response(pipeline, action: 'create')
          else
            ::Mcp::Tools::Base::Response.error(
              pipeline.errors.full_messages.join(', ').presence || 'Pipeline creation failed',
              reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST
            )
          end
        end

        def resolve_project(arguments)
          provided = PARENT_PARAMS.select { |key| arguments[key].present? }
          raise ArgumentError, 'Provide exactly one of: url or project_id' unless provided.one?

          identifier = provided.first == :url ? parse_parent_url(arguments[:url])[:path] : arguments[:project_id]
          find_parent_by_id_or_path!(:project, identifier)
        end

        def perform_update(arguments)
          raise ArgumentError, 'Provide pipeline_id to rename a pipeline' if arguments[:pipeline_id].blank?
          raise ArgumentError, 'Provide name to rename the pipeline' if arguments[:name].blank?

          pipeline = ::Ci::Pipeline.find_by_id(arguments[:pipeline_id])
          message = 'Pipeline not found or inaccessible.'

          unless pipeline
            return ::Mcp::Tools::Base::Response.error(
              message, reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND
            )
          end

          unless Ability.allowed?(current_user, :read_pipeline, pipeline)
            return ::Mcp::Tools::Base::Response.error(
              message, reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
            )
          end

          authorize_granular_token!(pipeline.project, [:update_pipeline_metadata], not_found_message: message)

          response = ::Ci::Pipelines::UpdateMetadataService
            .new(pipeline, current_user: current_user, params: { name: arguments[:name] })
            .execute

          return pipeline_response(response.payload, action: 'update') if response.success?

          # Readable but not renamable maps to the same uniform message; other
          # failures carry the service's own error strings.
          if response.reason == :forbidden
            return ::Mcp::Tools::Base::Response.error(
              message, reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
            )
          end

          ::Mcp::Tools::Base::Response.error(
            Array(response.payload).join(', ').presence || response.message,
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST
          )
        end

        def pipeline_response(pipeline, action:)
          structured_content = {
            action: action,
            id: pipeline.id,
            name: pipeline.name,
            status: pipeline.status,
            ref: pipeline.ref,
            web_url: "#{pipeline.project.web_url}/-/pipelines/#{pipeline.id}"
          }.compact

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(structured_content) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, structured_content)
        end
      end
    end
  end
end
