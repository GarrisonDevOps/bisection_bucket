# frozen_string_literal: true

module EE
  module AppConfig
    module InstanceMetadata
      extend ::Gitlab::Utils::Override

      # The plan of the license this instance runs under.
      #
      # Where subscriptions are held per namespace, the instance license says
      # nothing about what any given caller may do, so this reports nothing
      # rather than a plan that would be read as the caller's own.
      #
      # An expired trial (License#trial_expired?) can still be License.current,
      # but it grants no licensed feature (License#feature_available?), so it
      # reports the CE answer. An expired paid license keeps its plan, because
      # License#feature_available? still grants its features.
      override :plan
      def plan
        return if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        license = ::License.current
        return super if license.nil? || license.trial_expired?

        license.plan
      end
    end
  end
end
