# frozen_string_literal: true

module API
  module Security
    module DependencyFirewall
      class Evaluations < ::API::Base
        feature_category :dependency_firewall
        # Each evaluation costs several uncached package-metadata queries across two databases.
        urgency :low

        SESSION_HEADER = 'X-Gitlab-Dependency-Firewall-Session-Id'

        ERRORS = {
          not_enforced: {
            status: :unprocessable_entity,
            code: 'dependency_firewall_not_enforced',
            message: 'Dependency Firewall is not enabled for this project.'
          },
          evaluation_failed: {
            status: :service_unavailable,
            code: 'dependency_firewall_evaluation_failed',
            message: 'Dependency Firewall evaluation could not be completed.'
          }
        }.freeze

        before { authenticate! }

        helpers do
          # fetch without a default on purpose: a KeyError means the service grew a reason this
          # hash does not handle, and the 503 would tell a client to fail closed forever on our bug.
          def render_evaluation_error!(reason)
            if reason == :invalid_coordinate
              blank = %i[name version].select { |field| params[field].blank? }
              bad_request!("Package #{blank.join(' and ')} cannot be blank.")
            end

            error = ERRORS.fetch(reason)
            render_structured_api_error!({ message: error[:message], code: error[:code] }, error[:status])
          end
        end

        params do
          requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
        end
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Evaluate a package against Dependency Firewall policies for a project' do
            detail 'Evaluates a single package against the Dependency Firewall policies for a specified ' \
              'project. Available behind the `dependency_firewall_access` feature flag, disabled by default.'
            success code: 200, model: ::API::Entities::Security::DependencyFirewall::PackageEvaluation
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Dependency Firewall is not enabled' },
              { code: 429, message: 'Too many requests' },
              { code: 503, message: 'Evaluation could not be completed' }
            ]
            tags %w[dependency_firewall]
            # An experiment endpoint must stay out of the OpenAPI spec, so nothing generates a client
            # against a contract that can change without notice (doc/development/api_styleguide.md).
            hidden true
          end
          params do
            requires :ecosystem, type: String,
              values: ::Security::DependencyFirewall::EvaluatePackageService::ECOSYSTEMS,
              desc: 'Package ecosystem.'
            requires :name, type: String, limit: 255,
              desc: 'Package name. Maven names use the `groupId:artifactId` form.'
            requires :version, type: String, limit: 255,
              desc: 'Package version.'
            optional :operation, type: String,
              values: ::Security::DependencyFirewall::EvaluatePackageService::OPERATIONS.keys,
              default: 'download',
              desc: 'Package operation being evaluated.'
          end
          route_setting :authentication, job_token_allowed: true
          # No job-token policy, matching the enablement endpoint: a fine-grained policy describes
          # cross-project access, and this endpoint refuses cross-project tokens outright. A
          # same-project token reaches this write path only when its user holds the dedicated
          # evaluation permission checked below.
          route_setting :authorization, permissions: :create_dependency_firewall_evaluation,
            boundary_type: :project, skip_job_token_policies: true
          route_setting :lifecycle, :experiment
          post ':id/dependency_firewall/evaluate' do
            not_found! unless ::Security::DependencyFirewall::Availability.access_enabled?(user_project)

            # Before authorize!, so a cross-project token gets this message rather than a bare 403
            # from the membership check. A build has no need to ask another project's firewall
            # about a package, and the verdict names the policy that produced it.
            if current_user.from_ci_job_token? &&
                !current_user.ci_job_token_scope.self_referential?(user_project)
              forbidden!('A CI/CD job token can only evaluate packages for its own project.')
            end

            # Not :read_package: that ability is vetoed for every role when the package registry
            # is off, and the firewall evaluates upstream dependencies, not hosted packages.
            # See https://gitlab.com/gitlab-org/gitlab/-/issues/619521.
            authorize! :create_dependency_firewall_evaluation, user_project

            check_rate_limit!(:dependency_firewall_evaluation, scope: { project: user_project })

            result = ::Security::DependencyFirewall::EvaluatePackageService.new(
              project: user_project,
              current_user: current_user,
              ecosystem: params[:ecosystem],
              name: params[:name],
              version: params[:version],
              operation: params[:operation],
              session_id: request.headers[SESSION_HEADER]
            ).execute

            render_evaluation_error!(result.reason) unless result.success?

            # 200 rather than Grape's POST default of 201: the response is a verdict, not a resource
            # the caller can fetch back, so there is nothing to put in a Location header.
            status :ok
            present result.payload, with: ::API::Entities::Security::DependencyFirewall::PackageEvaluation
          end
        end
      end
    end
  end
end
