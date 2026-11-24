# frozen_string_literal: true

# Seeds continuous integration tables that had neither a factory nor a fixture, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
#
# Most rows go in with `insert_all` so they can carry the nulls model validations reject. The
# trigger is the exception: its token is generated and encrypted by the model.
class Gitlab::Seeder::ContinuousIntegration # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  attr_reader :user, :project, :pipeline, :artifacts

  def initialize
    @user = User.order(:id).first
    @pipeline = Ci::Pipeline.order(:id).first
    @project = @pipeline&.project || Project.order(:id).first
    @artifacts = Ci::JobArtifact.order(:id).limit(2).to_a
  end

  def seed!
    return warn_missing_dependencies unless user && project

    warn_missing_parents
    seed_triggers
    seed_burned_project_routes
    seed_pipeline_chat_data
    seed_job_artifact_reports
    seed_workload_variable_inclusions
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping continuous integration seeds: no user or project available"
  end

  # Naming the absent parents keeps a run that skips a section from reading like a run that
  # seeded everything.
  def warn_missing_parents
    missing = []
    missing << 'pipeline' if pipeline.nil?
    missing << 'job artifact' if artifacts.empty?
    return if missing.empty?

    warn "\nSkipping continuous integration seeds that need: #{missing.join(', ')}"
  end

  # Built through the model because the token is generated and encrypted there, and `insert_all`
  # would leave `token_encrypted` empty, which the model requires.
  def seed_triggers
    return if Ci::Trigger.exists?(project_id: project.id)

    Ci::Trigger.create!(project: project, owner: user, description: 'Seeded pipeline trigger')
    Ci::Trigger.create!(project: project, owner: user, description: nil)
    print '.'
  end

  # The model owns the insert and the conflict target, so calling it keeps the seeded row the
  # same shape the application writes.
  def seed_burned_project_routes
    Authn::BurnedProjectRoute.burn!(
      organization_id: project.organization_id,
      path: "#{project.full_path}-seeded-burned",
      project_id: project.id
    )
    print '.'
  end

  def seed_pipeline_chat_data
    return unless pipeline && chat_name

    Ci::PipelineChatData.insert_all(
      [{ pipeline_id: pipeline.id, partition_id: pipeline.partition_id,
         project_id: pipeline.project_id, chat_name_id: chat_name.id,
         response_url: 'https://example.com/seeded-chat-response' }],
      unique_by: %i[pipeline_id])
    print '.'
  end

  # One report records a validation failure and the other leaves the error null.
  def seed_job_artifact_reports
    return if artifacts.empty?

    statuses = Ci::JobArtifactReport.statuses

    rows = artifacts.each_with_index.map do |artifact, index|
      validated = index.zero?
      { job_artifact_id: artifact.id, partition_id: artifact.partition_id,
        project_id: artifact.project_id,
        status: validated ? statuses[:validated] : statuses[:faulty],
        validation_error: validated ? nil : 'Seeded validation failure' }
    end

    Ci::JobArtifactReport.insert_all(rows, unique_by: %i[job_artifact_id partition_id])
    print '.'
  end

  # Only the auto generated key is unique here, so the guard is what keeps a re-run idempotent.
  def seed_workload_variable_inclusions
    return unless workload
    return if Ci::Workloads::VariableInclusions.exists?(workload_id: workload.id)

    rows = %w[SEEDED_VARIABLE SEEDED_OTHER_VARIABLE].map do |variable_name|
      { workload_id: workload.id, partition_id: workload.partition_id,
        project_id: workload.project_id, variable_name: variable_name,
        created_at: now, updated_at: now }
    end

    # Partitioned, so the key `insert_all` infers from the model is not the real composite one.
    Ci::Workloads::VariableInclusions.insert_all(rows, unique_by: %i[id partition_id])
    print '.'
  end

  # Created when absent so the chat data below has something to point at.
  def chat_name
    @chat_name ||= ChatName.order(:id).first || ChatName.create!(
      user: user, team_id: 'seeded-team', team_domain: 'seeded', chat_id: 'seeded-chat-id',
      chat_name: 'seeded-chat-name')
  end

  def workload
    @workload ||= Ci::Workloads::Workload.order(:id).first || create_workload
  end

  def create_workload
    return unless pipeline

    Ci::Workloads::Workload.create!(project: pipeline.project, pipeline: pipeline)
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating continuous integration data"

  Gitlab::Seeder::ContinuousIntegration.new.seed!
end
