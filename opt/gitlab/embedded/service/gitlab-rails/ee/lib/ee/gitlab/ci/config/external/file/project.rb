# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Config
        module External
          module File
            module Project
              extend ::Gitlab::Utils::Override

              private

              override :project_access_allowed?
              def project_access_allowed?(user, project)
                super ||
                  security_policy_management_project_access_allowed?(project) ||
                  pipeline_execution_policy_file_access_allowed?(project)
              end

              def security_policy_management_project_access_allowed?(project)
                context.logger.instrument(:config_file_project_validate_access_policy) do
                  next false unless policy_management_project_access_allowed?
                  next false unless requesting_project
                  next false unless requesting_project.affected_by_security_policy_management_project?(project)

                  spp_allows_pipeline_access?(project)
                end
              end

              def spp_allows_pipeline_access?(project)
                ::Gitlab::SafeRequestStore.fetch(
                  ['Ci::Config::External::File::Project', 'spp_allows_pipeline_access', project.id]
                ) do
                  ::Security::OrchestrationPolicyConfiguration.policy_management_project?(project) &&
                    project.project_setting.spp_repository_pipeline_access
                end
              end

              def pipeline_execution_policy_file_access_allowed?(project)
                context.logger.instrument(:config_file_project_validate_policy_access) do
                  !!pipeline_execution_context&.ci_config_access_allowed?(
                    config_project: project, file_path: params[:file]
                  )
                end
              end

              def policy_management_project_access_allowed?
                pipeline_execution_context&.policy_management_project_access_allowed?
              end

              def pipeline_execution_context
                context.pipeline_policy_context&.pipeline_execution_context
              end

              # Nested includes mutate `context.project` to the immediately enclosing file's project, so we
              # read the pipeline's own project from the stable policy context instead.
              def requesting_project
                pipeline_execution_context.target_project
              end
            end
          end
        end
      end
    end
  end
end
