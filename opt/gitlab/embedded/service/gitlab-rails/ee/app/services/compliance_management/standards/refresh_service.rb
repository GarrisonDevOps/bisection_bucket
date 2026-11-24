# frozen_string_literal: true

module ComplianceManagement
  module Standards
    class RefreshService < BaseGroupService
      def execute
        return ServiceResponse.error(message: 'namespace must be a group') unless group.is_a?(Group)
        return ServiceResponse.error(message: "Access denied for user id: #{current_user&.id}") unless allowed?

        ::ComplianceManagement::Standards::RefreshWorker.perform_async({ 'group_id' => group.id,
                                                                        'user_id' => current_user&.id })

        progress = ::ComplianceManagement::StandardsAdherenceChecksTracker.new(group.id).progress

        # In case the RefreshWorker was not enqueued yet we will get an empty hash as a response from the
        # StandardsAdherenceChecksTracker. We don't want to calculate the total_checks here since it is an expensive
        # database operation, therefore, we send back a static value as 1 for total_checks and for checks_completed
        # we send 0, so that at the frontend we get 0% as the current progress of completed checks.
        progress = { started_at: Time.current.utc.to_s, total_checks: "1", checks_completed: "0" } if progress.blank?

        ServiceResponse.success(payload: progress)
      end

      private

      def allowed?
        Ability.allowed?(current_user, :read_compliance_adherence_report, group)
      end
    end
  end
end
