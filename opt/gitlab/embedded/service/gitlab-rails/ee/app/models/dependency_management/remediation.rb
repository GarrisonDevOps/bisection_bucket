# frozen_string_literal: true

module DependencyManagement
  # Last known auto-remediation state for one dependency in one manifest.
  # Keyed on the dependency's location rather than the vulnerability it fixes:
  # one bump resolves however many vulnerabilities that dependency has.
  class Remediation < ::SecApplicationRecord
    self.table_name = 'dependency_management_remediations'

    STATES = {
      open: 0,
      dismissed: 1,
      merged: 2
    }.freeze

    UNIQUE_INDEX = :idx_dm_remediations_on_project_purl_package_path_and_version

    belongs_to :project, optional: false
    belongs_to :merge_request, optional: true

    enum :purl_type, ::Enums::Sbom.purl_types
    enum :state, STATES

    # A nil id would otherwise match every row the loose foreign key orphaned.
    scope :for_merge_request, ->(merge_request) do
      merge_request.id ? where(merge_request_id: merge_request.id) : none
    end

    # Ingestion writes the same name to the component and the occurrence, and
    # matching on the component lets the lookup use its unique index.
    scope :without_installed_occurrence, -> do
      where_not_exists(
        ::Sbom::Occurrence
          .joins(:component, :component_version)
          .where('sbom_occurrences.project_id = dependency_management_remediations.project_id')
          .where('sbom_components.name = dependency_management_remediations.package_name')
          .where('sbom_components.purl_type = dependency_management_remediations.purl_type')
          .where('sbom_component_versions.version = dependency_management_remediations.current_version')
          .where("COALESCE(sbom_occurrences.input_file_path, '') = dependency_management_remediations.input_file_path")
      )
    end

    validates :purl_type, presence: true
    validates :state, presence: true
    # The unique index is the real guard; this only turns a duplicate into a
    # validation error rather than RecordNotUnique for callers that save.
    validates :package_name, presence: true, length: { maximum: 255 },
      uniqueness: { scope: [:project_id, :purl_type, :input_file_path, :current_version] }
    validates :current_version, presence: true, length: { maximum: 255 }
    validates :target_version, presence: true, length: { maximum: 255 }
    # '' is an unreported path. Empty rather than NULL so the unique index
    # keeps deduping, since Postgres treats NULLs as distinct.
    validates :input_file_path, exclusion: { in: [nil] }, length: { maximum: 1024 }

    RESET = %i[merge_request_id target_version state dismissed_at updated_at].freeze
    KEEP_DISMISSAL = %i[updated_at].freeze

    private_constant :RESET, :KEEP_DISMISSAL

    # Upsert: locking is per branch, and one branch can carry several installed versions.
    def self.record_proposal(
      project:, merge_request:, purl_type:, package_name:, input_file_path:, current_version:, target_version:)
      now = Time.current
      path = input_file_path.to_s

      # Unlocked on purpose: a close racing this read and upsert ends as if it ran
      # after, a no-op because the row then tracks the new merge request.
      existing = find_by(
        project_id: project.id,
        purl_type: purl_type,
        package_name: package_name,
        input_file_path: path,
        current_version: current_version
      )

      # record_timestamps would read the database clock instead.
      upsert_all(
        [{
          project_id: project.id,
          merge_request_id: merge_request.id,
          purl_type: ::Enums::Sbom.purl_types[purl_type],
          package_name: package_name,
          input_file_path: path,
          current_version: current_version,
          target_version: target_version,
          state: states[:open],
          dismissed_at: nil,
          created_at: now,
          updated_at: now
        }],
        unique_by: UNIQUE_INDEX,
        update_only: columns_to_overwrite(existing, target_version, purl_type),
        record_timestamps: false
      )
    end

    # Only a strictly higher target clears a dismissal, otherwise the decision
    # still stands.
    def self.columns_to_overwrite(existing, target_version, purl_type)
      return RESET unless existing&.dismissed?
      return RESET if higher_version?(target_version, existing.target_version, purl_type)

      KEEP_DISMISSAL
    end
    private_class_method :columns_to_overwrite

    # Uncomparable counts as higher: re-proposing beats going quiet.
    def self.higher_version?(candidate, other, purl_type)
      dialect = ::Enums::Sbom.semver_dialects_purl_type(purl_type)
      return true if dialect.blank?

      result = SemverDialects.parse_version(dialect, candidate) <=> SemverDialects.parse_version(dialect, other)
      result.nil? || result > 0
    rescue SemverDialects::Error
      true
    end
    private_class_method :higher_version?

    # Matched on the installed version too: a dismissal recorded against an
    # older install must not suppress proposals after the dependency moved.
    def self.for_occurrence(project, occurrence)
      return unless occurrence

      find_by(
        project_id: project.id,
        purl_type: occurrence.purl_type,
        package_name: occurrence.component_name,
        input_file_path: occurrence.input_file_path.to_s,
        current_version: occurrence.version
      )
    end

    def self.transition_for_merge_request(merge_request, state)
      dismissing = state.to_s == 'dismissed'
      now = Time.current

      for_merge_request(merge_request).update_all(
        state: states.fetch(state.to_s),
        # The close is the moment the decision was made, which is earlier than
        # this job runs. Anything but a dismissal leaves no dismissal to date.
        dismissed_at: dismissing ? (merge_request.metrics&.latest_closed_at || now) : nil,
        updated_at: now
      )
    end

    # Open rows no event can move: the merge request is gone, or it closed or merged before
    # its close or merge event could still land. The delete re-checks updated_at, so a row
    # moved to a new merge request after the lookup is kept.
    def self.delete_open_without_live_merge_request(settled_before:)
      settled = open.where(updated_at: ...settled_before)
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- the worker calls this per each_batch batch
      rows = settled.pluck(:id, :merge_request_id)
      candidates = ::MergeRequest.id_in(rows.filter_map(&:last).uniq)
      live_ids = candidates.opened_or_locked.or(candidates.updated_after(settled_before)).pluck(:id).to_set
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      dead_ids = rows.filter_map { |id, merge_request_id| id unless live_ids.include?(merge_request_id) }
      settled.id_in(dead_ids).delete_all
    end

    # Dismissed only, so a merged bump cannot be resurrected.
    def self.withdraw_dismissal_for_merge_request(merge_request)
      for_merge_request(merge_request).dismissed.update_all(
        state: states[:open],
        dismissed_at: nil,
        updated_at: Time.current
      )
    end
  end
end
