# frozen_string_literal: true

module Security
  module ScanProfiles
    class ProjectAttachService
      include Gitlab::Utils::StrongMemoize
      include Security::ScanProfiles::SchedulesTriageCoverageUpdate

      AUDIT_EVENT_NAME = 'security_scan_profile_attached_to_project'
      REPLACED_AUDIT_EVENT_NAME = 'security_scan_profile_replaced_on_project'
      MAX_PROJECTS = 500
      REPLACING_MODES = %i[set replace].freeze

      def self.execute(...)
        new(...).execute
      end

      def self.unsupported_mode_error(profile, mode)
        return unless mode == :fill_scan_gaps
        return if Security::AnalyzerProjectStatus.analyzer_types.key?(profile.scan_type)

        "Scan type '#{profile.scan_type}' does not support the FILL_SCAN_GAPS mode."
      end

      def initialize(profile:, current_user:, projects: [], mode: :set)
        @profile = profile
        @projects = projects
        @current_user = current_user
        @mode = mode
        @errors = []
      end

      def execute
        return { errors: errors } unless valid_request?

        inserted_ids = attach_profile
        affected_ids = inserted_ids | replaced.keys
        handle_errors(inserted_ids)
        initialize_profile_statuses(inserted_ids)
        create_audit_events(affected_ids)
        schedule_status_updates(affected_ids)

        { errors: errors }
      rescue StandardError => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
        error_result('An error has occurred during profile attachment')
      end

      private

      attr_reader :profile, :projects, :current_user, :errors, :mode

      def valid_request?
        errors << 'At least one project must be provided' if projects.empty?
        errors << "Cannot attach profile to more than #{MAX_PROJECTS} items at once." if projects.size > MAX_PROJECTS
        errors << mode_error if mode_error
        errors.empty?
      end

      def mode_error
        self.class.unsupported_mode_error(profile, mode)
      end
      strong_memoize_attr :mode_error

      def attach_profile
        Security::ScanProfileProject.transaction do
          remove_same_type_links if REPLACING_MODES.include?(mode)
          insert_under_limit
        end
      end

      def target_projects
        projects.index_by(&:id).values_at(*target_project_ids)
      end
      strong_memoize_attr :target_projects

      def target_project_ids
        project_ids = projects.map(&:id)

        case mode
        when :replace
          project_ids & with_same_type_profile(project_ids)
        when :fill_profile_gaps
          project_ids - with_same_type_profile(project_ids)
        when :fill_scan_gaps
          project_ids - with_same_type_profile(project_ids) - with_scan_coverage(project_ids)
        else
          project_ids
        end
      end

      def with_same_type_profile(project_ids)
        Security::ScanProfileProject.project_ids_with_profile_type(project_ids, profile.namespace_id, profile.scan_type)
      end

      # Aggregated types also count setting-based coverage, so only their pipeline-based row counts as scan coverage.
      def with_scan_coverage(project_ids)
        coverage_type = Security::AnalyzersStatus::AggregatedTypesHandler::TYPE_MAPPINGS
          .dig(profile.scan_type.to_sym, :pipeline_type) || profile.scan_type

        Security::AnalyzerProjectStatus.covered_project_ids(project_ids, coverage_type)
      end

      def replaced
        @replaced ||= {}
      end

      def remove_same_type_links
        old_profiles = Security::ScanProfile.other_with_same_type(profile).index_by(&:id)
        return if old_profiles.empty?

        rows = Security::ScanProfileProject
          .by_project_id(target_projects.map(&:id))
          .for_scan_profiles(old_profiles.keys)
          .delete_all_returning(:project_id, :security_scan_profile_id)
        return if rows.empty?

        rows.each do |row|
          (replaced[row['project_id']] ||= []) << old_profiles[row['security_scan_profile_id']]
        end

        rows.group_by { |row| row['security_scan_profile_id'] }.each do |profile_id, profile_rows|
          mark_statuses_unconfigured(profile_rows.map { |row| row['project_id'] }, profile_id)
        end
      end

      def mark_statuses_unconfigured(project_ids, profile_id)
        Security::ScanProfileProjectStatus
          .for_projects_and_profile(project_ids, profile_id)
          .update_all(
            status: Security::ScanProfileProjectStatus.statuses[:not_configured],
            consecutive_failure_count: 0,
            consecutive_success_count: 0,
            updated_at: now
          )
      end

      # `archived` and `traversal_ids` are denormalized onto the join row because
      # `security_scan_profiles_projects` lives in `gitlab_sec` and `projects` in
      # `gitlab_main_org`, so queries on this table cannot join to `projects`.
      def insert_under_limit
        return [] if target_projects.empty? # an empty VALUES list is invalid SQL

        sql = <<~SQL
          INSERT INTO security_scan_profiles_projects
            (project_id, security_scan_profile_id, archived, traversal_ids, created_at, updated_at)
          SELECT candidate_project_id, ?, candidate_archived,
            candidate_traversal_ids, NOW(), NOW()
          FROM (VALUES #{candidate_row_placeholders})
            AS candidates(candidate_project_id, candidate_archived, candidate_traversal_ids)
          WHERE (
            SELECT COUNT(*) FROM security_scan_profiles_projects spp
            WHERE spp.project_id = candidate_project_id
            AND EXISTS (
              SELECT 1 FROM security_scan_profiles sp
              WHERE sp.id = spp.security_scan_profile_id
              AND sp.deleted_at IS NULL
            )
          ) < ?
          ON CONFLICT (project_id, security_scan_profile_id) DO NOTHING
          RETURNING project_id;
        SQL

        sanitized_sql = Security::ScanProfileProject.sanitize_sql_array(
          [sql, profile.id, *candidate_rows.flatten(1), Security::ScanProfileProject::MAX_PROFILES_PER_PROJECT]
        )

        # rubocop:disable Database/AvoidUsingPluckWithoutLimit: -- False positive. This is not a relation.
        Security::ScanProfileProject.connection.execute(sanitized_sql)
          .pluck('project_id') # rubocop:disable CodeReuse/ActiveRecord -- reading query result
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit:
      end

      # Returns {#target_projects} with the associations
      # {Security::ScanProfileProject.preload_archived_state} loads.
      #
      # @return [Array<Project>]
      def preloaded_projects
        Security::ScanProfileProject.preload_archived_state(target_projects)
      end

      # Builds the bind values for each candidate row of the {#insert_under_limit} insert.
      # `traversal_ids` is bound as an array literal: `ARRAY[?]` binds an empty one as `ARRAY[NULL]`.
      #
      # @return [Array<Array(Integer, Boolean, String)>] project ID, archived state and `traversal_ids` literal
      def candidate_rows
        preloaded_projects.map do |project|
          [
            project.id,
            project.self_or_ancestors_archived?,
            "{#{project.namespace.traversal_ids_as_sql}}"
          ]
        end
      end
      strong_memoize_attr :candidate_rows

      # Builds the `VALUES` list for the {#insert_under_limit} insert, with one
      # placeholder tuple for each of the {#candidate_rows}.
      #
      # @return [String]
      def candidate_row_placeholders
        Array.new(candidate_rows.size, '(?, ?, ?::bigint[])').join(', ')
      end

      def handle_errors(inserted_ids)
        requested_ids = target_projects.map(&:id)
        return if inserted_ids.size == requested_ids.size

        potential_error_ids = requested_ids - inserted_ids
        already_attached_ids = Security::ScanProfileProject
          .by_project_id(potential_error_ids)
          .for_scan_profiles(profile.id)
          .limit(potential_error_ids.size)
          .pluck(:project_id) # rubocop:disable CodeReuse/ActiveRecord -- specific use case

        maxed_out_ids_set = (potential_error_ids - already_attached_ids).to_set
        maxed_out_projects = target_projects.select { |p| maxed_out_ids_set.include?(p.id) }
        return if maxed_out_projects.empty?

        # Preload routes to avoid N+1 queries when accessing project.full_path
        ActiveRecord::Associations::Preloader.new(records: maxed_out_projects, associations: [:route]).call

        maxed_out_projects.each do |project|
          errors << "Project '#{project.name}' (#{project.full_path}) has reached the maximum limit of scan profiles."
        end
      end

      def initialize_profile_statuses(inserted_ids)
        return if inserted_ids.empty?

        records = inserted_ids.map do |project_id|
          {
            project_id: project_id,
            security_scan_profile_id: profile.id,
            status: Security::ScanProfileProjectStatus.statuses[:success],
            consecutive_failure_count: 0,
            consecutive_success_count: 0,
            created_at: now,
            updated_at: now
          }
        end

        Security::ScanProfileProjectStatus.upsert_all(
          records,
          unique_by: [:project_id, :security_scan_profile_id]
        )
      end

      def schedule_status_updates(project_ids)
        return unless project_ids.present?

        Security::AnalyzersStatus::ScheduleSettingChangedUpdateWorker.perform_async(project_ids, profile.scan_type)
        schedule_triage_coverage_update(project_ids, scan_type: profile.scan_type)
      end

      def create_audit_events(affected_project_ids)
        return if current_user.blank? || affected_project_ids.empty?

        affected_ids_set = affected_project_ids.to_set
        affected_projects = projects.select { |p| affected_ids_set.include?(p.id) }
        return if affected_projects.empty?

        # Preload routes to avoid N+1 queries when accessing project.full_path
        ActiveRecord::Associations::Preloader.new(records: affected_projects, associations: [:route]).call

        replaced_projects, attached_projects = affected_projects.partition { |p| replaced.key?(p.id) }
        audit_projects(REPLACED_AUDIT_EVENT_NAME, replaced_projects) { |p| build_replacement_audit_event(p) }
        audit_projects(AUDIT_EVENT_NAME, attached_projects) { |p| build_audit_event(p) }
      end

      def audit_projects(event_name, audited_projects)
        return if audited_projects.empty?

        ::Gitlab::Audit::Auditor.audit(audit_context(event_name)) do
          audited_projects.each { |project| ::Gitlab::Audit::EventQueue.push(yield(project)) }
        end
      end

      def audit_context(name)
        {
          name: name,
          author: current_user,
          scope: profile.namespace,
          target: profile
        }
      end

      def build_replacement_audit_event(project)
        old_profiles = replaced.fetch(project.id).sort_by(&:id)

        AuditEvents::BuildService.new(
          author: current_user,
          scope: project,
          target: profile,
          created_at: now,
          message: "Replaced security scan profile '#{old_profiles.map(&:name).to_sentence}' " \
            "with '#{profile.name}' on project '#{project.full_path}'",
          additional_details: {
            event_name: REPLACED_AUDIT_EVENT_NAME,
            organization_id: project.organization_id,
            profile_id: profile.id,
            profile_name: profile.name,
            previous_profile_ids: old_profiles.map(&:id),
            previous_profile_names: old_profiles.map(&:name),
            scan_type: profile.scan_type,
            project_id: project.id,
            project_path: project.full_path
          }
        ).execute
      end

      def build_audit_event(project)
        AuditEvents::BuildService.new(
          author: current_user,
          scope: project,
          target: profile,
          created_at: now,
          message: "Attached security scan profile '#{profile.name}' to project '#{project.full_path}'",
          additional_details: {
            event_name: AUDIT_EVENT_NAME,
            organization_id: project.organization_id,
            profile_id: profile.id,
            profile_name: profile.name,
            scan_type: profile.scan_type,
            project_id: project.id,
            project_path: project.full_path
          }
        ).execute
      end

      def now
        Time.zone.now
      end
      strong_memoize_attr :now

      def error_result(message)
        {
          errors: [message]
        }
      end
    end
  end
end
