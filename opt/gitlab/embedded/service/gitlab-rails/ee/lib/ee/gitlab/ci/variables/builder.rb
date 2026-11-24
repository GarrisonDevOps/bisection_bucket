# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Variables
        module Builder
          extend ::Gitlab::Utils::Override

          override :initialize
          def initialize(pipeline)
            super

            @scan_execution_policies_variables_builder =
              ::Gitlab::Ci::Variables::Builder::ScanExecutionPolicies.new(pipeline)
          end

          override :scoped_variables_for_pipeline_seed
          def scoped_variables_for_pipeline_seed(job_attr, environment:, kubernetes_namespace:, user:, trigger:)
            apply_execution_policy_variables(
              super,
              name: job_attr[:name],
              options: job_attr[:options],
              yaml_variables: job_attr[:yaml_variables]
            )
          end

          # When adding new variables, consider either adding or commenting out them in the following methods:
          # - scoped_variables_for_pipeline_seed
          override :scoped_variables
          def scoped_variables(job, environment:, dependencies:)
            apply_execution_policy_variables(
              super,
              name: job.name,
              options: job.options,
              yaml_variables: job.yaml_variables
            )
          end

          private

          attr_reader :scan_execution_policies_variables_builder

          # On-demand DAST scans should not receive protected variables, even when
          # running on a protected branch. The DAST analyzer doesn't need customer
          # secrets (it uses profile-based authentication via DastSiteProfile#secret_ci_variables),
          # and exposing protected variables would be a privilege escalation since
          # developers can now trigger these scans on protected branches.
          # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/242141
          override :protected_ref?
          def protected_ref?
            return false if pipeline.ondemand_dast_scan?

            super
          end

          override :user_defined_variables
          def user_defined_variables(options:, environment:, protected_ref:, job_variables: nil)
            ::Security::ExecutionPolicy::VariablesOverride.new(project: project, job_options: options)
                                                          .apply_variables_override(super)
          end

          def apply_execution_policy_variables(variables, name:, options:, yaml_variables:)
            variables_override = ::Security::ExecutionPolicy::VariablesOverride
              .new(project: project, job_options: options)

            # The legacy builder appends SEP variables at the end of the chain.
            # Skip it only for SEP jobs that use the new `variables_override` mechanism;
            # all other jobs (regular, old SEP without metadata, PEP) still go through it.
            # Remove with https://gitlab.com/gitlab-org/gitlab/-/work_items/591130.
            unless variables_override.replaces_legacy_scan_execution_policy_variables_builder?
              variables.concat(
                scan_execution_policies_variables_builder.variables(name, yaml_variables)
              )
            end

            variables_override.apply_highest_precedence(variables, yaml_variables)
          end
        end
      end
    end
  end
end
