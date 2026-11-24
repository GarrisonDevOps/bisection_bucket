# frozen_string_literal: true

class DependencyListEntity < Grape::Entity
  include RequestAwareEntity
  include DependencyMalwareGating

  present_collection true, :dependencies

  # Resolved for the whole page here, because Sbom::Occurrence#malware_status falls back to a
  # query per occurrence when nothing has preloaded it.
  expose :dependencies, using: DependencyEntity do |list|
    preload_malware_status(list[:dependencies])
  end

  expose :report, if: ->(_, options) { options[:pipeline] && can_read_job_path? } do
    # This data structure is kept only to avoid a breaking change to the dependency list export.
    # `pipeline` is from `project.latest_ingested_sbom_pipeline` and as long as it exists we
    # can assume that report ingestion was successful.
    expose :status, proc: ->(_) { :ok }

    expose :job_path do |_, options|
      project_pipeline_path(project, options[:pipeline].id)
    end

    expose :generated_at do |_, options|
      options[:pipeline].finished_at
    end
  end

  private

  def preload_malware_status(dependencies)
    occurrences = dependencies.to_a
    return occurrences unless render_malware_field?

    ::Sbom::MalwareAdvisoriesPreloader.new(occurrences).execute

    occurrences
  end

  def can_read_job_path?
    can?(request.user, :read_pipeline, project)
  end

  def project
    request.try(:project)
  end
end
