# frozen_string_literal: true

class PagesWorker # rubocop:disable Scalability/IdempotentWorker
  include ApplicationWorker
  include Sidekiq::InterruptionsExhausted

  RETRIES_EXHAUSTED_MESSAGE = 'The Pages deployment worker ran out of retries'
  INTERRUPTIONS_EXHAUSTED_MESSAGE = 'The Pages deployment worker was interrupted too many times'

  data_consistency :always

  sidekiq_options retry: 3
  feature_category :pages
  loggable_arguments 0, 1
  worker_resource_boundary :cpu

  sidekiq_retries_exhausted do |job, _exception|
    new.perform_failure(job['args'].second, RETRIES_EXHAUSTED_MESSAGE)
  end

  # An OOM kill bypasses UpdatePagesService's rescue, leaving pages:deploy statuses running.
  sidekiq_interruptions_exhausted do |job|
    new.perform_failure(job['args'].second, INTERRUPTIONS_EXHAUSTED_MESSAGE)
  end

  def perform(action, *arg)
    deploy(*arg) if action == 'deploy'
  end

  def deploy(build_id)
    build = Ci::Build.find_by_id(build_id)

    Projects::UpdatePagesService.new(build.project, build).execute
  end

  def perform_failure(build_id, message)
    build = Ci::Build.find_by_id(build_id)
    return unless build

    allow_failure = !::Gitlab::Pages::DeploymentValidations.new(build.project, build).latest_build?

    build.pipeline.generic_commit_statuses.by_name('pages:deploy').running.find_each do |status|
      status.allow_failure = allow_failure
      status.description = message
      status.drop(:script_failure)
    end

    PagesDeployment.destroy_incomplete_for_build(build.id)
  end
end
