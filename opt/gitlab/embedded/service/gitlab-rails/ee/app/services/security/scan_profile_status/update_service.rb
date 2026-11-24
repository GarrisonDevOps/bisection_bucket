# frozen_string_literal: true

module Security
  module ScanProfileStatus
    class UpdateService
      BUILD_TO_STATUS = {
        'success' => :success,
        'failed' => :failed,
        'canceled' => :failed,
        'skipped' => :failed
      }.freeze

      # Higher value = worse status = higher priority when deduplicating
      STATUS_PRIORITY = {
        success: 0,
        failed: 1
      }.freeze

      MAX_CONSECUTIVE_COUNT = 32767 # consecutive_failure_count/consecutive_success_count are smallint columns.

      ON_DUPLICATE_SQL = <<~SQL
        build_id = EXCLUDED.build_id,
        last_scan_at = EXCLUDED.last_scan_at,
        consecutive_failure_count = CASE WHEN EXCLUDED.status = %{success_status} THEN 0
          ELSE LEAST(security_scan_profile_project_statuses.consecutive_failure_count + 1, %{max_count}) END,
        consecutive_success_count = CASE WHEN EXCLUDED.status = %{success_status}
          THEN LEAST(security_scan_profile_project_statuses.consecutive_success_count + 1, %{max_count}) ELSE 0 END,
        status = CASE
          WHEN EXCLUDED.status = %{success_status} THEN %{success_status}
          WHEN security_scan_profile_project_statuses.consecutive_failure_count + 1 >= %{failed_threshold}
            THEN %{failed_status}
          ELSE %{warning_status}
        END,
        updated_at = NOW()
        WHERE security_scan_profile_project_statuses.build_id IS NULL
          OR security_scan_profile_project_statuses.build_id < EXCLUDED.build_id
      SQL

      def initialize(pipeline)
        @pipeline = pipeline
        @project = pipeline&.project
      end

      def execute
        return unless project&.licensed_feature_available?(:security_scan_profiles)

        build_data_by_profile = dedupe_builds_by_profile(profile_triggered_builds)
        return if build_data_by_profile.empty?

        # Locking the links keeps a concurrent detach/replace from leaving a stale status row behind.
        ScanProfileProject.transaction do
          linked_ids = ScanProfileProject.lock_linked_profile_ids(project.id, build_data_by_profile.keys)
          build_data_by_profile.slice!(*linked_ids)
          next if build_data_by_profile.empty?

          upsert_records = build_data_by_profile.map do |profile_id, (status, build)|
            build_upsert_attributes(profile_id, status, build)
          end

          ScanProfileProjectStatus.upsert_all(
            upsert_records,
            unique_by: [:project_id, :security_scan_profile_id],
            on_duplicate: Arel.sql(on_duplicate_sql)
          )
        end
      end

      private

      attr_reader :pipeline, :project

      def on_duplicate_sql
        format(ON_DUPLICATE_SQL,
          success_status: statuses[:success],
          warning_status: statuses[:warning],
          failed_status: statuses[:failed],
          failed_threshold: ScanProfileProjectStatus::FAILED_THRESHOLD,
          max_count: MAX_CONSECUTIVE_COUNT)
      end

      def dedupe_builds_by_profile(builds)
        builds.each_with_object({}) do |build, build_data_by_profile|
          profile_id = resolve_profile_id(build)
          next unless profile_id

          status = BUILD_TO_STATUS[build.status] || :failed
          current_status, _ = build_data_by_profile[profile_id]
          next if current_status && STATUS_PRIORITY[current_status] > STATUS_PRIORITY[status]

          build_data_by_profile[profile_id] = [status, build]
        end
      end

      def profile_triggered_builds
        pipeline.builds
          .with_build_source(:security_scan_profiles)
          .with_statuses(Ci::HasStatus::COMPLETED_STATUSES)
          .latest
          .order_id_asc
      end

      def resolve_profile_id(build)
        redis_profile_id = begin
          ::Gitlab::Ci::Pipeline::SecurityScanProfiles::ScanProfileMappingStore.profile_id_for_build(build)
        rescue ::Redis::BaseError => e
          Gitlab::ErrorTracking.track_exception(e, extra: { build_id: build.id, pipeline_id: pipeline.id })
          nil
        end

        redis_profile_id || resolve_profile_id_from_build(build)
      end

      def resolve_profile_id_from_build(build)
        scan_type = detect_scan_type(build)
        return unless scan_type

        profiles = profiles_by_scan_type[scan_type.to_s] || []

        if profiles.size > 1
          Gitlab::AppLogger.warn(
            message: 'Multiple scan profiles found for scan type, skipping fallback resolution',
            scan_type: scan_type,
            project_id: project.id,
            profile_count: profiles.size
          )
          return
        end

        profiles.first&.id
      end

      def profiles_by_scan_type
        @profiles_by_scan_type ||= project.security_scan_profiles.not_deleted.scanner.group_by(&:scan_type)
      end

      def detect_scan_type(build)
        report_keys = build_reports(build).map(&:to_sym)
        profile_types = Enums::Security.scan_profile_types.keys

        matched = (report_keys & profile_types).first
        return matched if matched

        return :dependency_scanning if report_keys.include?(:cyclonedx) &&
          build.name.include?('dependency_scanning')

        nil
      end

      def build_reports(build)
        build.options.dig(:artifacts, :reports)&.keys || []
      end

      def build_upsert_attributes(profile_id, status, build)
        succeeded = status == :success

        {
          project_id: project.id,
          security_scan_profile_id: profile_id,
          status: succeeded ? statuses[:success] : statuses[:warning],
          consecutive_failure_count: succeeded ? 0 : 1,
          consecutive_success_count: succeeded ? 1 : 0,
          last_scan_at: build.started_at || build.created_at,
          build_id: build.id,
          created_at: Time.current,
          updated_at: Time.current
        }
      end

      def statuses
        ScanProfileProjectStatus.statuses
      end
    end
  end
end
