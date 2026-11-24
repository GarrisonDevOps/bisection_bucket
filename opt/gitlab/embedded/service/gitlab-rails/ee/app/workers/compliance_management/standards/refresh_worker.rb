# frozen_string_literal: true

module ComplianceManagement
  module Standards
    class RefreshWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!
      urgency :low

      feature_category :compliance_management

      STANDARDS_ADHERENCE_CHECK_WORKERS = [
        ::ComplianceManagement::Standards::Gitlab::PreventApprovalByAuthorGroupWorker,
        ::ComplianceManagement::Standards::Gitlab::PreventApprovalByCommitterGroupWorker,
        ::ComplianceManagement::Standards::Gitlab::AtLeastTwoApprovalsGroupWorker,
        ::ComplianceManagement::Standards::Gitlab::SastGroupWorker,
        ::ComplianceManagement::Standards::Gitlab::DastGroupWorker,
        ::ComplianceManagement::Standards::Soc2::AtLeastOneNonAuthorApprovalGroupWorker
      ].freeze

      TOTAL_STANDARDS_ADHERENCE_CHECKS = STANDARDS_ADHERENCE_CHECK_WORKERS.count

      def perform(args = {})
        group_id = args['group_id']
        user_id = args['user_id']
        group = Group.find_by_id(group_id)

        return unless group

        # Don't enqueue worker again if redis key exists. The key has a TTL of 24 hours
        # and we prevent running the checks again within 24 hours.
        return if ::ComplianceManagement::StandardsAdherenceChecksTracker.new(group_id).already_enqueued?

        ::ComplianceManagement::StandardsAdherenceChecksTracker
          .new(group_id).track_progress(TOTAL_STANDARDS_ADHERENCE_CHECKS * group.all_projects.count)

        STANDARDS_ADHERENCE_CHECK_WORKERS.each do |worker|
          worker.perform_async({ 'group_id' => group_id, 'user_id' => user_id, 'track_progress' => true })
        end
      end
    end
  end
end
