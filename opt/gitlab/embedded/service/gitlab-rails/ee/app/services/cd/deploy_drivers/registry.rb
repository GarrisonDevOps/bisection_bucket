# frozen_string_literal: true

module Cd
  module DeployDrivers
    class Registry
      GEMS = {
        'argo-rollouts' => 'gitlab-deploy-driver-argo-rollouts'
      }.freeze

      # Not in GEMS: the engine is not a driver and no environment binds to it.
      ORCHESTRATION_GEM = 'gitlab-cd-driver-orchestration'

      def self.find(driver_ref)
        gem_name = GEMS[driver_ref]
        return unless gem_name

        (@drivers ||= {})[driver_ref] ||= Driver.for_gem(gem_name)
      end

      def self.orchestrator
        @orchestrator ||= Orchestrator.for_gem(ORCHESTRATION_GEM)
      end

      def self.driver_refs
        GEMS.keys
      end
    end
  end
end
