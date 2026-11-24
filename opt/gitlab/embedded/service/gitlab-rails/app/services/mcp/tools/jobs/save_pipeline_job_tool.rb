# frozen_string_literal: true

module Mcp
  module Tools
    module Jobs
      class SavePipelineJobTool < Base::GraphqlTool
        include Mcp::Tools::Concerns::CiVariables
        include Mcp::Tools::Concerns::GranularTokenAuthorization
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::UrlParser

        register_version VERSIONS[:v0_1_0], {
          operation_name: 'jobPlay',
          graphql_operation: load_graphql('jobs/play_job.mutation.graphql')
        }

        def build_variables
          job = find_job!

          {
            input: {
              id: job.to_global_id.to_s,
              variables: ci_variables
            }.compact
          }
        end

        private

        def process_result(result)
          if resource_access_denied?(result)
            return ::Mcp::Tools::Base::Response.error(
              ::Gitlab::Graphql::Authorize::AuthorizeResource::RESOURCE_ACCESS_ERROR,
              reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED
            )
          end

          processed_result = super
          return processed_result if processed_result[:isError]

          job = processed_result.dig(:structuredContent, 'job')

          return ::Mcp::Tools::Base::Response.error('Operation returned no job data') if job.blank?

          payload = format_job(job)
          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(payload) }]

          ::Mcp::Tools::Base::Response.success(formatted_content, payload)
        end

        def find_job!
          project, job_id = resolve_target

          authorize_granular_token!(project, [:play_job], not_found_message: 'Job not found or inaccessible')

          # rubocop:disable Database/AvoidUnpartitionedCiRelations -- no partition key available
          job = project.builds.find_by_id(job_id)
          # rubocop:enable Database/AvoidUnpartitionedCiRelations

          raise ResourceNotFoundError, 'Job not found or inaccessible' unless job

          unless Ability.allowed?(current_user, :play_job, job)
            raise ResourceForbiddenError, 'Job not found or inaccessible'
          end

          raise ArgumentError, 'Job must be a playable manual job' unless job.manual? && job.playable?

          if params[:variables].present? && !Ability.allowed?(current_user, :set_pipeline_variables, job.project)
            raise ResourceForbiddenError, 'You do not have permission to pass variables to this job'
          end

          job
        end

        def resolve_target
          unless params[:url].present?
            unless params[:project_id].present? && params[:job_id].present?
              raise ArgumentError, 'Provide url, or project_id and job_id'
            end

            return [find_project!(params[:project_id]), params[:job_id]]
          end

          target = parse_job_url(params[:url])
          project = find_project!(target[:project_path])
          job_id = target[:job_id]

          if params[:project_id].present? && find_project!(params[:project_id]) != project
            raise ArgumentError, 'project_id does not match the job URL'
          end

          if params[:job_id].present? && params[:job_id] != job_id
            raise ArgumentError, 'job_id does not match the job URL'
          end

          [project, job_id]
        end

        def format_job(job)
          id = GlobalID.parse(job['id'])&.model_id.to_i
          pipeline_id = GlobalID.parse(job.dig('pipeline', 'id'))&.model_id.to_i

          {
            id: id,
            name: job['name'],
            status: job['status']&.downcase,
            stage: job.dig('stage', 'name'),
            pipeline_id: pipeline_id,
            web_url: web_url(job['webPath']),
            pipeline_web_url: web_url(job.dig('pipeline', 'path'))
          }
        end

        def web_url(path)
          return unless path

          URI.join(::Gitlab.config.gitlab.url, path).to_s
        end
      end
    end
  end
end
