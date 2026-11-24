# frozen_string_literal: true

module API
  module Security
    module DependencyFirewall
      class Enablement < ::API::Base
        feature_category :dependency_firewall

        before { authenticate! }

        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
        end
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Retrieve status of Dependency Firewall for a project' do
            detail 'Retrieves the status of Dependency Firewall for a specified project. Use this endpoint to ' \
              'determine whether to skip the firewall for an entire run. Projects with the firewall turned ' \
              'off return a successful response rather than `404 Not Found`, so you can tell them apart ' \
              'from projects you cannot access.'
            success code: 200, model: ::API::Entities::Security::DependencyFirewall::Enablement
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 429, message: 'Too many requests' }
            ]
            tags %w[dependency_firewall]
            # An experiment endpoint must stay out of the OpenAPI spec, so nothing generates a client
            # against a contract that can change without notice (doc/development/api_styleguide.md).
            # While this holds, the generated spec carries a `Dependency firewall` tag that no
            # operation references; removing `hidden` at general availability consumes it.
            hidden true
          end
          route_setting :authentication, job_token_allowed: true
          # No job-token policy: the fine-grained policies describe cross-project access, and this
          # endpoint refuses cross-project tokens outright, so declaring one would advertise a
          # control an operator cannot actually configure here.
          route_setting :authorization, permissions: :read_project,
            boundary_type: :project, skip_job_token_policies: true
          route_setting :lifecycle, :experiment
          get ':id/dependency_firewall/enablement' do
            # Own key rather than :project_api: a client polls this once per invocation, and sharing
            # a budget with ordinary project reads lets either starve the other.
            check_rate_limit_by_user_or_ip!(:dependency_firewall_enablement)

            # No authorize! call: user_project resolves through find_project!, which is what enforces
            # :read_project and turns an unreadable project into 404.
            project = user_project

            # A job token may only ask about its own project. Without this, a project that allowlists
            # another one inbound would expose its firewall posture to that project's pipelines, and
            # that is not a fact another project's build needs.
            if current_user.from_ci_job_token? && !current_user.ci_job_token_scope.self_referential?(project)
              forbidden!('A CI/CD job token can only check the Dependency Firewall status of its own project.')
            end

            # While the flag is off the endpoint must answer 404, because an experiment endpoint is
            # not supposed to exist yet (doc/development/api_styleguide.md). The body still carries the
            # answer, so a client skips the firewall instead of reading this as a project it cannot see.
            unless ::Security::DependencyFirewall::Availability.access_enabled?(project)
              render_structured_api_error!({ enabled: false }, :not_found)
            end

            enabled = ::Security::DependencyFirewall::Availability.enforced_for?(project)

            present({ enabled: enabled },
              with: ::API::Entities::Security::DependencyFirewall::Enablement)
          end
        end
      end
    end
  end
end
