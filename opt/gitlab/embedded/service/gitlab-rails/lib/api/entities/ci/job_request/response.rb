# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Response < Grape::Entity
          expose :id
          expose :token
          expose :allow_git_fetch

          expose :job_info, using: Entities::Ci::JobRequest::JobInfo do |model|
            model
          end

          expose :git_info, using: Entities::Ci::JobRequest::GitInfo do |model|
            model
          end

          expose :runner_info, using: Entities::Ci::JobRequest::RunnerInfo do |model|
            model
          end

          expose :runner_inputs, as: :inputs
          expose :runner_variables, as: :variables
          expose :steps, using: Entities::Ci::JobRequest::Step, if: ->(job) { job.run_steps.blank? }, documentation: { is_array: true }

          expose :runtime_hooks, as: :hooks, using: Entities::Ci::JobRequest::Hook, documentation: { is_array: true }
          expose :image, using: Entities::Ci::JobRequest::Image
          expose :services, using: Entities::Ci::JobRequest::Service, documentation: { is_array: true }
          expose :artifacts, using: Entities::Ci::JobRequest::Artifacts, documentation: { is_array: true }
          expose :cache, using: Entities::Ci::JobRequest::Cache, documentation: { is_array: true }
          expose :credentials, using: Entities::Ci::JobRequest::Credentials, documentation: { is_array: true }
          expose :features
          expose :dependencies do |job, options|
            Entities::Ci::JobRequest::Dependency.represent(job.all_dependencies, options.merge(running_job: job))
          end

          expose :run, if: ->(job) { job.run_steps.present? } do |job|
            job.run_steps.to_json
          end

          expose :suspend_options, if: ->(build, _) { build.suspend_options.present? }
        end
      end
    end
  end
end

API::Entities::Ci::JobRequest::Response.prepend_mod_with('API::Entities::Ci::JobRequest::Response')
