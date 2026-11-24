# frozen_string_literal: true

module EE
  module ServiceDesk
    module EmailRateLimiter
      extend ::Gitlab::Utils::Override

      private

      override :plan_limits
      def plan_limits
        return super unless ::ServiceDesk::PaidNamespaceProbation.new(project.root_namespace).active?

        ::GitlabSubscriptions::SystemDefined::Plan.free.actual_limits
      end
    end
  end
end
