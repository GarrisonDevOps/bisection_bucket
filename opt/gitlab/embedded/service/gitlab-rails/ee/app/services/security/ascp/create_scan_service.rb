# frozen_string_literal: true

module Security
  module Ascp
    class CreateScanService
      include Gitlab::ExclusiveLeaseHelpers

      LOCK_TTL = 1.minute
      LOCK_RETRIES = 10
      LOCK_SLEEP_SEC = 0.5.seconds
      COMPONENT_ASSOCIATION_DELAY = 15.minutes

      def initialize(current_user:, project:, params:)
        @current_user = current_user
        @project = project
        @params = params
      end

      def execute
        unless Ability.allowed?(@current_user, :create_ascp_scan, @project)
          return ServiceResponse.error(message: _('Insufficient permissions'), reason: :forbidden)
        end

        in_lock(lock_key, ttl: LOCK_TTL, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP_SEC) do
          scan = build_scan
          if scan.save
            schedule_component_association
            ServiceResponse.success(payload: { scan: scan })
          else
            ServiceResponse.error(message: scan.errors.full_messages.to_sentence)
          end
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        ServiceResponse.error(message: 'Failed to obtain lock for scan creation. Please retry.')
      end

      private

      # Components arrive via separate AscpComponentCreate calls 20-100s after the scan
      # row exists, so an immediate run matches an empty component set. Replace with an
      # explicit finished state: https://gitlab.com/gitlab-org/gitlab/-/work_items/625027
      def schedule_component_association
        return unless Feature.enabled?(:ascp_component_vulnerability_association, @project)

        Vulnerabilities::UpdateAscpAssociationsWorker.perform_in(COMPONENT_ASSOCIATION_DELAY, @project.id)
      end

      def lock_key
        "ascp:scan_sequence:#{@project.id}"
      end

      def build_scan
        Scan.new(
          project: @project,
          scan_sequence: next_sequence,
          base_scan: resolve_base_scan,
          **@params.except(:base_scan_id)
        )
      end

      def next_sequence
        Scan.next_scan_sequence_for(@project.id)
      end

      def resolve_base_scan
        return unless @params[:base_scan_id]

        Scan.find_for_project(@params[:base_scan_id], @project.id)
      end
    end
  end
end
