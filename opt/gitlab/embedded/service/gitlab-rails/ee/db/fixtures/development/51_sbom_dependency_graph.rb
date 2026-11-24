# frozen_string_literal: true

# Seeds an SBOM dependency graph, whose tables are empty in the upgrade stop dump, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
#
# Two occurrences are seeded rather than one, because a graph path needs a distinct ancestor and
# descendant, and that pair is what gives `ancestors` and `top_level_ancestor` a meaningful value.
class Gitlab::Seeder::SbomDependencyGraph # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  DIRECT = { name: 'seeded-direct-dependency', version: '1.2.3' }.freeze
  TRANSITIVE = { name: 'seeded-transitive-dependency', version: '4.5.6' }.freeze
  DEPENDENCIES = [DIRECT, TRANSITIVE].freeze
  DEPENDENCY_NAMES = DEPENDENCIES.pluck(:name).freeze

  INPUT_FILE_PATH = 'seeded/package-lock.json'
  PACKAGE_MANAGER = 'npm'
  LICENSES = [{ spdx_identifier: 'MIT', name: 'MIT License', url: 'https://spdx.org/licenses/MIT.html' }].freeze
  SOURCE = {
    category: 'development',
    input_file: { path: INPUT_FILE_PATH },
    source_file: { path: 'seeded/package.json' },
    package_manager: { name: PACKAGE_MANAGER },
    language: { name: 'JavaScript' }
  }.freeze

  attr_reader :vulnerability, :project, :pipeline, :tracked_context

  # Everything hangs off one pipeline so the rows share a project. A freshly seeded database has
  # no vulnerabilities at all, so one is preferred as the starting point but not required.
  def initialize
    @vulnerability = Vulnerability
      .where(finding_id: Vulnerabilities::Finding.where.not(latest_pipeline_id: nil).select(:id))
      .order(:id)
      .first
    @pipeline = pipeline_with_sha
    @project = @pipeline&.project
    @vulnerability = nil unless @vulnerability&.project_id == @project&.id
    @tracked_context = tracked_context_for(@project)
  end

  def seed!
    return warn_missing_dependencies unless project && pipeline && tracked_context && organization_id

    occurrences = seed_occurrences(seed_source, seed_component_versions(seed_components))

    seed_occurrence_refs(occurrences)
    seed_graph_path(occurrences)
    seed_occurrence_vulnerability(occurrences)
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping SBOM dependency graph seeds: no pipeline with a project, organization " \
      "and tracked context available"
  end

  # `commit_sha` is NOT NULL on both tables while `Ci::Pipeline` validates `sha` only for
  # non-imported rows, so neither branch may hand back a pipeline without one.
  def pipeline_with_sha
    preferred = Vulnerabilities::Finding.find_by(id: @vulnerability&.finding_id)&.latest_finding_pipeline
    return preferred if preferred&.sha.present?

    Ci::Pipeline.where.not(sha: [nil, '']).order(:id).first
  end

  # Reuses an existing tracked context so the common path stays off Gitaly, which the service
  # reaches for the default branch name. Ingestion only ever links a ref to a tracked context.
  def tracked_context_for(project)
    return unless project

    existing = Security::ProjectTrackedContext
      .tracked.where(project_id: project.id).order(is_default: :desc, id: :desc).first
    return existing if existing

    Security::ProjectTrackedContexts::FindOrCreateService
      .project_default_branch(project).execute.payload[:tracked_context]
  end

  def organization_id
    project&.organization_id
  end

  def seed_source
    Sbom::Source.insert_all(
      [{ source_type: Sbom::Source.source_types[:dependency_scanning], source: SOURCE,
         organization_id: organization_id, created_at: now, updated_at: now }],
      unique_by: %i[source_type source organization_id])
    print '.'

    Sbom::Source.find_by(source_type: :dependency_scanning, source: SOURCE, organization_id: organization_id)
  end

  def seed_components
    rows = DEPENDENCIES.map do |dependency|
      { name: dependency[:name], purl_type: ::Enums::Sbom.purl_types[:npm],
        component_type: ::Enums::Sbom.component_types[:library],
        organization_id: organization_id, created_at: now, updated_at: now }
    end

    Sbom::Component.insert_all(rows, unique_by: %i[name purl_type component_type organization_id])
    print '.'

    # Looked up on the whole unique index, since the same name can exist under another purl type.
    Sbom::Component
      .where(name: DEPENDENCY_NAMES, purl_type: ::Enums::Sbom.purl_types[:npm],
        component_type: ::Enums::Sbom.component_types[:library], organization_id: organization_id)
      .index_by(&:name)
  end

  def seed_component_versions(components)
    rows = DEPENDENCIES.map do |dependency|
      { component_id: components.fetch(dependency[:name]).id, version: dependency[:version],
        organization_id: organization_id, created_at: now, updated_at: now }
    end

    Sbom::ComponentVersion.insert_all(rows, unique_by: %i[component_id version organization_id])
    print '.'

    # Looked up on the whole unique index, since a component can carry more than one version.
    DEPENDENCIES.each_with_object({}) do |dependency, result|
      result[dependency[:name]] = Sbom::ComponentVersion.find_by!(
        component_id: components.fetch(dependency[:name]).id, version: dependency[:version],
        organization_id: organization_id)
    end
  end

  def seed_occurrences(source, versions)
    rows = DEPENDENCIES.map { |dependency| occurrence_row(dependency, versions.fetch(dependency[:name]), source) }

    Sbom::Occurrence.insert_all(rows, unique_by: %i[uuid])
    print '.'

    Sbom::Occurrence.where(uuid: rows.pluck(:uuid)).index_by(&:component_name)
  end

  # Only the transitive dependency carries the vulnerability, so the counters follow whether the
  # link row is written, and that row leaves the nullable columns unset for a migration to trip on.
  def occurrence_row(dependency, version, source)
    direct = dependency == DIRECT
    linked = !direct && vulnerability

    { project_id: project.id, pipeline_id: pipeline.id, source_id: source.id,
      component_id: version.component_id, component_version_id: version.id,
      commit_sha: pipeline.sha,
      uuid: ::Sbom::OccurrenceUUID.generate(project_id: project.id, component_id: version.component_id,
        component_version_id: version.id, source_id: source.id),
      component_name: dependency[:name], package_manager: direct ? PACKAGE_MANAGER : nil,
      input_file_path: INPUT_FILE_PATH, licenses: direct ? LICENSES : [],
      highest_severity: linked ? ::Enums::Vulnerability.severity_levels[vulnerability.severity] : nil,
      vulnerability_count: linked ? 1 : 0,
      traversal_ids: project.namespace.traversal_ids,
      archived: project.self_or_ancestors_archived?,
      ancestors: direct ? [{}] : [DIRECT],
      reachability: ::Enums::Sbom.reachability_types[direct ? :in_use : :not_found],
      created_at: now, updated_at: now }
  end

  def seed_occurrence_refs(occurrences)
    rows = occurrences.values.map do |occurrence|
      { sbom_occurrence_id: occurrence.id, security_project_tracked_context_id: tracked_context.id,
        project_id: project.id, pipeline_id: pipeline.id, commit_sha: pipeline.sha,
        reachability: ::Enums::Sbom.reachability_types[occurrence.reachability] }
    end

    Sbom::OccurrenceRef.insert_all(rows, unique_by: %i[sbom_occurrence_id security_project_tracked_context_id])
    print '.'
  end

  # The table has no unique index, so a re-run is guarded by the edge it would duplicate.
  def seed_graph_path(occurrences)
    ancestor = occurrences.fetch(DIRECT[:name])
    descendant = occurrences.fetch(TRANSITIVE[:name])
    return if Sbom::GraphPath.exists?(ancestor_id: ancestor.id, descendant_id: descendant.id)

    Sbom::GraphPath.insert_all(
      [{ ancestor_id: ancestor.id, descendant_id: descendant.id, project_id: project.id,
         path_length: 1, top_level_ancestor: true, created_at: now, updated_at: now }])
    print '.'
  end

  def seed_occurrence_vulnerability(occurrences)
    return unless vulnerability

    occurrence = occurrences.fetch(TRANSITIVE[:name])

    Sbom::OccurrencesVulnerability.insert_all(
      [{ sbom_occurrence_id: occurrence.id, vulnerability_id: vulnerability.id, project_id: project.id,
         vulnerability_occurrence_id: vulnerability.finding_id, created_at: now, updated_at: now }],
      unique_by: %i[sbom_occurrence_id vulnerability_id project_id])
    print '.'
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating SBOM dependency graph data"

  Gitlab::Seeder::SbomDependencyGraph.new.seed!
end
