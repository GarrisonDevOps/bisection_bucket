# frozen_string_literal: true

# Seeds CI sync event, job input and deployment tables that are empty in the upgrade stop dump, so
# migrations touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::CiSyncEventsAndDeployments # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  INPUT_NAMES = %w[seeded_input seeded_input_without_value].freeze
  SHORT_REF = 'refs/heads/seeded-deleted-branch'
  LONG_REF = "refs/heads/#{'a' * 1013}".freeze
  SEEDED_SHAS = %w[a1b2c3d4e5f60718293a4b5c6d7e8f9012345678
                   b2c3d4e5f60718293a4b5c6d7e8f901234567890].freeze
  SEEDED_NAME = 'seeded-finished-build'

  attr_reader :pipelines, :build, :deployment

  def initialize
    @pipelines = finished_pipelines
    @build = Ci::Build.where.not(finished_at: nil).order(:id).first || create_finished_build
    # The earliest deployments belong to projects that have no merge requests when this runs, so
    # the lookup prefers one that can fill `deployment_merge_requests` and falls back to any
    # deployment for the two seeds that only read a project id off it.
    @deployment = Deployment.where(project_id: MergeRequest.select(:target_project_id)).order(:id).first ||
      Deployment.order(:id).first
  end

  # Each table is guarded on its own parent, so one missing parent does not cost the others.
  def seed!
    warn_missing_parents
    seed_finished_pipeline_sync_events
    seed_job_inputs
    seed_project_with_pipeline_variables
    seed_deployment_merge_requests
    seed_ref_deletions
  end

  private

  # `14_pipelines.rb` only seeds `Project.not_mass_generated`, which is empty in the dev fixtures
  # job, so a finished pipeline and build are created there rather than leaving three tables empty.
  def finished_pipelines
    found = Ci::Pipeline.where.not(finished_at: nil).where.not(project_id: nil)
                        .order(:id).limit(2).to_a
    return found if found.any?

    create_finished_pipelines
  end

  # Two of them, because the sync event rows cover both sides of `processed`.
  def create_finished_pipelines
    project = Project.order(:id).first
    return [] if project.nil?

    SEEDED_SHAS.map do |sha|
      project.ci_pipelines.create!(ref: 'master', sha: sha, source: :push,
        status: 'success', finished_at: finished_at)
    end
  end

  def create_finished_build
    pipeline = pipelines.first
    return if pipeline.nil?

    stage = Ci::Stage.create!(pipeline: pipeline, project: pipeline.project,
      name: SEEDED_NAME, position: 0)
    Ci::Build.create!(pipeline: pipeline, ci_stage: stage, project: pipeline.project,
      ref: pipeline.ref, name: SEEDED_NAME, status: 'success',
      scheduling_type: :stage, finished_at: finished_at)
  end

  def finished_at
    @finished_at ||= 1.hour.ago
  end

  # Naming the absent parents keeps a run that seeds nothing from reading like a run that worked.
  def warn_missing_parents
    missing = []
    missing << 'finished pipeline' if pipelines.empty?
    missing << 'finished build' if build.nil?
    missing << 'deployment' if deployment.nil?
    return if missing.empty?

    warn "\nSkipping CI sync seeds that need: #{missing.join(', ')}"
  end

  # `partition` is an ignored column, so the database default assigns it. The pair covers both
  # sides of `processed`, which is what the `pending` scope filters on.
  def seed_finished_pipeline_sync_events
    pipelines.each_with_index do |pipeline, index|
      next if Ci::FinishedPipelineChSyncEvent.exists?(pipeline_id: pipeline.id)

      Ci::FinishedPipelineChSyncEvent.create!(
        pipeline_id: pipeline.id, project_namespace_id: pipeline.project.project_namespace_id,
        pipeline_finished_at: pipeline.finished_at, processed: index > 0)
      print '.'
    end
  end

  # `value` is encrypted by the model, so a row written straight to the table would hold plaintext.
  # It is also nullable, and the second input leaves it unset.
  def seed_job_inputs
    return unless build

    [{ name: INPUT_NAMES.first, value: { 'seeded' => true } }, { name: INPUT_NAMES.last, value: nil }]
      .each do |attrs|
        next if Ci::JobInput.exists?(job_id: build.id, partition_id: build.partition_id, name: attrs[:name])

        Ci::JobInput.create!(job: build, project_id: build.project_id, **attrs)
        print '.'
      end
  end

  def seed_project_with_pipeline_variables
    project_id = build&.project_id || deployment&.project_id
    return if project_id.nil? || Ci::ProjectWithPipelineVariable.exists?(project_id: project_id)

    Ci::ProjectWithPipelineVariable.create!(project_id: project_id)
    print '.'
  end

  # The service links merge requests from the deployment's own project, which is what the row's
  # `project_id` has to match. `environment_id` is nullable and the second row omits it.
  def seed_deployment_merge_requests
    return unless deployment

    merge_requests = MergeRequest.where(target_project_id: deployment.project_id)
      .order(:id).limit(2).to_a
    merge_requests.each_with_index do |merge_request, index|
      next if DeploymentMergeRequest.exists?(deployment_id: deployment.id, merge_request_id: merge_request.id)

      DeploymentMergeRequest.create!(
        deployment: deployment, merge_request: merge_request, project_id: deployment.project_id,
        environment_id: index == 0 ? deployment.environment_id : nil)
      print '.'
    end
  end

  # `ref` is limited to 1024 characters and the second deletion sits on that limit. The statuses
  # cover both sides of the `status_pending` scope the partition detach check reads.
  def seed_ref_deletions
    project_id = build&.project_id || deployment&.project_id
    return if project_id.nil?

    [[SHORT_REF, :pending], [LONG_REF, :processed]].each do |ref, status|
      next if BatchedGitRefUpdates::Deletion.exists?(project_id: project_id, ref: ref)

      BatchedGitRefUpdates::Deletion.create!(project_id: project_id, ref: ref, status: status)
      print '.'
    end
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating CI sync event and deployment data"

  Gitlab::Seeder::CiSyncEventsAndDeployments.new.seed!
end
