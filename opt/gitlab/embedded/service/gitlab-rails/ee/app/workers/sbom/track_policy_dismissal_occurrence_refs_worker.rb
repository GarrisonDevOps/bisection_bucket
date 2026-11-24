# frozen_string_literal: true

module Sbom
  class TrackPolicyDismissalOccurrenceRefsWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :dependency_management
    idempotent!

    def handle_event(event)
      policy_dismissal = ::Security::PolicyDismissal.find_by_id(event.data[:security_policy_dismissal_id])
      return unless policy_dismissal

      ::Sbom::TrackPolicyDismissalOccurrenceRefsService.new(policy_dismissal).execute
    end
  end
end
