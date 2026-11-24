# frozen_string_literal: true

# Seeds the dependency management tables, which had neither a factory nor a fixture, so
# migrations touching them were never exercised by db:migrate:multi-version-upgrade.
#
# The upload table is a list partition of `uploads` keyed on `model_type`, so it is filled by
# attaching an upload to the export part rather than written directly.
class Gitlab::Seeder::DependencyManagement # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  UPLOADER = 'AttachmentUploader'
  PART_FILE = 'seeded-dependency-list-export-part.json'

  attr_reader :project, :author, :organization

  def initialize
    @project = Project.order(:id).first
    @author = User.order(:id).first
    @organization = Organizations::Organization.find_by(id: @project&.organization_id)
  end

  def seed!
    return warn_missing_dependencies unless project && author && organization

    seed_source_packages
    seed_remediations

    export = dependency_list_export
    return unless export

    part = seed_export_parts(export)
    seed_part_upload(part) if part
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping dependency management seeds: no project, user or organization available"
  end

  def seed_source_packages
    return if Sbom::SourcePackage.exists?(organization_id: organization.id)

    purl_types = Sbom::SourcePackage.purl_types

    rows = [
      { name: 'seeded-source-package', purl_type: purl_types[:composer],
        organization_id: organization.id, created_at: now, updated_at: now },
      { name: 'seeded-other-source-package', purl_type: purl_types[:gem],
        organization_id: organization.id, created_at: now, updated_at: now }
    ]

    Sbom::SourcePackage.insert_all(rows)
    print '.'
  end

  # One open remediation with no merge request, and one already merged that points at one, so the
  # nullable association is covered from both sides. A merged remediation always has the merge
  # request it was merged through, so without one the second row stays open rather than claiming
  # a merge that never happened.
  def seed_remediations
    return if DependencyManagement::Remediation.exists?(project_id: project.id)

    merge_request = MergeRequest.where(target_project_id: project.id).order(:id).first
    purl_types = DependencyManagement::Remediation.purl_types
    states = DependencyManagement::Remediation.states

    rows = [
      { project_id: project.id, merge_request_id: nil, purl_type: purl_types[:composer],
        state: states[:open],
        package_name: 'seeded-package', input_file_path: 'Gemfile.lock',
        current_version: '1.0.0', target_version: '1.0.1', dismissed_at: nil,
        created_at: now, updated_at: now },
      { project_id: project.id, merge_request_id: merge_request&.id, purl_type: purl_types[:gem],
        state: merge_request ? states[:merged] : states[:open],
        package_name: 'seeded-other-package', input_file_path: '',
        current_version: '2.0.0', target_version: '2.1.0', dismissed_at: nil,
        created_at: now, updated_at: now }
    ]

    DependencyManagement::Remediation.insert_all(rows)
    print '.'
  end

  # A finished export must have a file the uploader can resolve, which a seeded row cannot have,
  # so this one stays in the state that does not require one. Exactly one of group, organization
  # and project may be set, so the organization is left to the export part.
  def dependency_list_export
    existing = Dependencies::DependencyListExport.where(project_id: project.id).order(:id).first
    return existing if existing

    Dependencies::DependencyListExport.insert_all(
      [{ project_id: project.id, group_id: nil, pipeline_id: nil, user_id: author.id,
         organization_id: nil, status: 0, export_type: 0,
         file: nil, file_store: nil, created_at: now, updated_at: now }])
    print '.'

    Dependencies::DependencyListExport.where(project_id: project.id).order(:id).first
  end

  # `start_id` and `end_id` bound a range of sbom occurrences. They carry no foreign key, so the
  # part does not need those rows to exist.
  def seed_export_parts(export)
    existing = Dependencies::DependencyListExport::Part.find_by(dependency_list_export_id: export.id)
    return existing if existing

    Dependencies::DependencyListExport::Part.insert_all(
      [{ dependency_list_export_id: export.id, organization_id: organization.id,
         start_id: 1, end_id: 1000, file: PART_FILE, file_store: 1,
         created_at: now, updated_at: now }])
    print '.'

    Dependencies::DependencyListExport::Part.find_by(dependency_list_export_id: export.id)
  end

  # `uploads` is partitioned on `model_type`, so this row lands in
  # dependency_list_export_part_uploads.
  def seed_part_upload(part)
    model_type = 'Dependencies::DependencyListExport::Part'
    return if Upload.exists?(model_type: model_type, model_id: part.id)

    # The composite primary key `insert_all` would infer from the partitioned table is not usable,
    # so the conflict target names the real one.
    Upload.insert_all(
      [{ model_type: model_type, model_id: part.id, uploader: UPLOADER, mount_point: 'file',
         path: "uploads/-/system/#{PART_FILE}", size: 2048, store: 1,
         organization_id: organization.id, created_at: now }],
      unique_by: %i[id model_type])
    print '.'
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating dependency management data"

  Gitlab::Seeder::DependencyManagement.new.seed!
end
