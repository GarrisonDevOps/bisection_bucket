# frozen_string_literal: true

module EE
  module API
    module Internal
      module Ci
        module JobRouter
          extend ActiveSupport::Concern

          prepended do
            helpers ::API::Helpers::KasHelpers

            before do
              authenticate_gitlab_kas_request!
            end

            helpers do
              include ::Gitlab::Utils::StrongMemoize

              def ensure_admission_control_enabled_for_runner!(runner)
                return if ::Feature.enabled?(:job_router_admission_control, runner)

                render_api_error!('Admission Control is not available. Please contact your administrator.', 501)
              end
            end

            namespace 'internal' do
              namespace 'ci' do
                namespace 'agents' do
                  namespace 'runnerc' do
                    helpers ::EE::API::Helpers::RunnerControllerHelpers

                    before do
                      check_runner_controller_token!
                    end

                    desc 'Gets agent info for runnerc' do
                      detail 'Retrieves agent info for runnerc (Runner Controllers) for the given token'
                      success code: 200
                      failure [
                        { code: 401, message: '401 Unauthorized' }
                      ]
                      tags %w[job_router runner_controller]
                    end
                    route_setting :authentication, runner_controller_token_allowed: true
                    route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                    get '/info' do
                      status 200
                      {
                        agent_id: runner_controller.id
                      }
                    end
                  end
                end

                namespace 'job_router' do
                  namespace 'runner_controllers' do
                    helpers ::API::Ci::Helpers::Runner

                    before do
                      authenticate_runner_from_header!
                      ::Gitlab::ApplicationContext.push(runner: current_runner_from_header)
                    end

                    desc 'Get applicable runner controllers to use for job admission control' do
                      detail 'Retrieves all applicable runner controller to use for ' \
                        'job admission control in the job router'
                      success code: 200
                      failure [
                        { code: 401, message: '401 Unauthorized' },
                        { code: 501, message: '501 Not Implemented' }
                      ]
                      tags %w[jobs job_router]
                    end
                    route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                    get '/job_admission' do
                      ensure_job_router_enabled_for_runner!(current_runner_from_header)
                      ensure_admission_control_enabled_for_runner!(current_runner_from_header)

                      controllers = ::Ci::RunnerController
                        .applicable_for(current_runner_from_header)
                        .select(:id, :state)

                      status 200
                      {
                        runner_controllers: controllers.map { |c| { id: c.id, state: c.state } }
                      }
                    end
                  end

                  namespace 'jobs' do
                    helpers ::API::Ci::Helpers::Runner

                    before do
                      authenticate_job!
                    end

                    desc 'Update job state from Job Router' do
                      detail 'Updates the state of a job from the Job Router'
                      success code: 200
                      failure [
                        { code: 400, message: '400 Bad Request' },
                        { code: 403, message: '403 Forbidden' },
                        { code: 404, message: '404 Not Found' }
                      ]
                      tags %w[jobs job_router]
                    end
                    params do
                      requires :id, type: Integer, desc: "Job's ID"
                      requires :token, type: String, desc: "Job's authentication token"
                      requires :state, type: String, values: %w[failed],
                        desc: "Job's state (only 'failed' is supported)"
                      optional :failure_reason, type: String, values: %w[job_router_failure],
                        desc: "Job's failure reason (only 'job_router_failure' is allowed)"
                      optional :failure_message, type: String,
                        desc: "Custom failure message (only allowed with failure_reason=job_router_failure)"
                      optional :runtime_environment_key, type: String,
                        limit: ::Ci::RuntimeEnvironment::ENVIRONMENT_KEY_MAX_LENGTH,
                        desc: "Runtime environment key emitted by the runner on job suspension"
                    end
                    route_setting :authorization, skip_granular_token_authorization: :job_token_auth
                    put ':id' do
                      check_rate_limit!(:runner_jobs_api,
                        scope: { job_token_sha: ::Gitlab::CryptoHelper.sha256(job_token) }, user: nil)

                      ::Gitlab::Metrics.add_event(:update_build)

                      # Build service parameters
                      service_params = params.slice(:state, :failure_reason, :failure_message,
                        :runtime_environment_key).compact

                      service = ::Ci::UpdateBuildStateService.new(current_job, service_params)

                      service.execute.then do |result|
                        track_ci_minutes_usage!(current_job)

                        header 'Job-Status', current_job.status
                        header 'X-GitLab-Trace-Update-Interval', result.backoff
                        status result.status
                        body result.status.to_s
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
