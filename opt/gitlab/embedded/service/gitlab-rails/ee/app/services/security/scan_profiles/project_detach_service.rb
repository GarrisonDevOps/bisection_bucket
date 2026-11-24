# frozen_string_literal: true

module Security
  module ScanProfiles
    class ProjectDetachService
      include Gitlab::Utils::StrongMemoize
      include Security::ScanProfiles::SchedulesTriageCoverageUpdate

      AUDIT_EVENT_NAME = 'security_scan_profile_detached_from_project'
      MAX_PROJECTS = 500

      def self.execute(...)
        new(...).execute
      end

      def initialize(profile:, current_user:, projects: [])
        @profile = profile
        @projects = projects
        @current_user = current_user
        @errors = []
      end

      def execute
        return { errors: errors } unless valid_projects?

        detached_project_ids = delete_and_return_project_ids
        mark_profile_statuses_unconfigured(detached_project_ids)
        create_audit_events(detached_project_ids)
        schedule_status_updates(detached_project_ids)

        { errors: errors }
      rescue StandardError => e
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
        error_result('An error has occurred during profile detachment')
      end

      private

      attr_reader :profile, :projects, :current_user, :errors

      def valid_projects?
        errors << 'At least one project must be provided' if projects.empty?
        errors << "Cannot detach profile from more than #{MAX_PROJECTS} items at once." if projects.size > MAX_PROJECTS
        errors.empty?
      end

      def delete_and_return_project_ids
        Security::ScanProfileProject
          .by_project_id(projects.map(&:id))
          .for_scan_profiles(profile.id)
          .delete_all_returning(:project_id)
          .pluck('project_id') # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- pluck on Array, not AR relation
      end

      def mark_profile_statuses_unconfigured(detached_project_ids)
        return if detached_project_ids.empty?

        Security::ScanProfileProjectStatus
          .for_projects_and_profile(detached_project_ids, profile.id)
          .update_all(
            status: Security::ScanProfileProjectStatus.statuses[:not_configured],
            consecutive_failure_count: 0,
            consecutive_success_count: 0,
            updated_at: now
          )
      end

      def schedule_status_updates(project_ids)
        return unless project_ids.present?

        Security::AnalyzersStatus::ScheduleSettingChangedUpdateWorker.perform_async(project_ids, profile.scan_type)
        schedule_triage_coverage_update(project_ids, scan_type: profile.scan_type)
      end

      def create_audit_events(detached_project_ids)
        return if current_user.blank? || detached_project_ids.empty?

        detached_ids_set = detached_project_ids.to_set
        detached_projects = projects.select { |p| detached_ids_set.include?(p.id) }
        return if detached_projects.empty?

        # Preload routes to avoid N+1 queries when accessing project.full_path
        ActiveRecord::Associations::Preloader.new(records: detached_projects, associations: [:route]).call

        ::Gitlab::Audit::Auditor.audit(audit_context) do
          detached_projects.each do |project|
            event = build_audit_event(project)
            ::Gitlab::Audit::EventQueue.push(event)
          end
        end
      end

      def audit_context
        {
          author: current_user,
          scope: profile.namespace,
          target: profile,
          name: AUDIT_EVENT_NAME
        }
      end

      def build_audit_event(project)
        AuditEvents::BuildService.new(
          author: current_user,
          scope: project,
          target: profile,
          created_at: now,
          message: "Detached security scan profile '#{profile.name}' from project '#{project.full_path}'",
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
