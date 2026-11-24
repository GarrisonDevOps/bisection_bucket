# frozen_string_literal: true

module Cd
  module Rollouts
    class StartWorker
      include ApplicationWorker

      data_consistency :sticky

      idempotent!
      worker_has_external_dependencies!
      feature_category :continuous_delivery

      def perform(rollout_id)
        ::Cd::Rollout.find_by_id(rollout_id).try do |rollout|
          ::Cd::Rollouts::StartService.new(rollout).execute
        end
      end
    end
  end
end
