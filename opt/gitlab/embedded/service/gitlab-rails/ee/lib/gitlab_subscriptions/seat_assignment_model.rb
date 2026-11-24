# frozen_string_literal: true

module GitlabSubscriptions
  module SeatAssignmentModel
    class << self
      def enabled?(source)
        return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return false unless source

        root_ancestor = source.root_ancestor

        return false unless root_ancestor.group_namespace?
        return false unless ::Feature.enabled?(:seat_assignment_model, root_ancestor)

        !!root_ancestor.namespace_settings&.seat_assignment_model_enabled?
      end
    end
  end
end
