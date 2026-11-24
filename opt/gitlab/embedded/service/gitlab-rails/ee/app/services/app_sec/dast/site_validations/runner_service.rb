# frozen_string_literal: true

module AppSec
  module Dast
    module SiteValidations
      class RunnerService < BaseProjectService
        def execute
          return ServiceResponse.error(message: _('Insufficient permissions')) unless allowed?

          unless available_runners_exist?
            return ServiceResponse.error(message: _('No suitable runners available for DAST validation'))
          end

          service = Ci::CreatePipelineService.new(project, current_user, ref: project.default_branch_or_main)
          result = service.execute(:ondemand_dast_validation, content: ci_configuration.to_yaml, variables_attributes: dast_site_validation_variables)

          if result.success?
            ServiceResponse.success(payload: dast_site_validation)
          else
            dast_site_validation.fail_op

            result
          end
        end

        private

        def allowed?
          can?(current_user, :create_on_demand_dast_scan, project)
        end

        def dast_site_validation
          @dast_site_validation ||= params[:dast_site_validation]
        end

        def ci_configuration
          ci_config = {
            'include' => [{ 'template' => 'Security/DAST-Runner-Validation.gitlab-ci.yml' }]
          }

          ci_config['validation'] = { 'tags' => [dast_validation_tag] } if tagged_runners_available?

          ci_config
        end

        def dast_validation_tag
          'dast-validation-runner'
        end

        def available_runners_exist?
          tagged_runners_available? || untagged_runners_available?
        end

        def runners_available?(tagged: false)
          params = {
            project: project,
            status: 'active'
          }

          if tagged
            params[:tag_name] = dast_validation_tag
          else
            params[:run_untagged] = true
          end

          ::Ci::RunnersFinder.new(
            current_user: current_user,
            params: params
          ).execute.exists?
        end

        strong_memoize_attr def tagged_runners_available?
          runners_available?(tagged: true)
        end

        strong_memoize_attr def untagged_runners_available?
          runners_available?(tagged: false)
        end

        def dast_site_validation_variables
          [
            { key: 'DAST_SITE_VALIDATION_ID', value: String(dast_site_validation.id) },
            { key: 'DAST_SITE_VALIDATION_HEADER', value: ::DastSiteValidation::HEADER },
            { key: 'DAST_SITE_VALIDATION_STRATEGY', value: dast_site_validation.validation_strategy },
            { key: 'DAST_SITE_VALIDATION_TOKEN', value: dast_site_validation.dast_site_token.token },
            { key: 'DAST_SITE_VALIDATION_URL', value: dast_site_validation.validation_url }
          ]
        end
      end
    end
  end
end
