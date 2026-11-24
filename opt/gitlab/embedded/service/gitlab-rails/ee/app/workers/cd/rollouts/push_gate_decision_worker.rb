# frozen_string_literal: true

module Cd
  module Rollouts
    class PushGateDecisionWorker
      include ApplicationWorker

      data_consistency :sticky

      idempotent!
      worker_has_external_dependencies!
      feature_category :continuous_delivery
      loggable_arguments 2

      sidekiq_retries_exhausted do |job, exception|
        Gitlab::ErrorTracking.track_exception(
          exception,
          rollout_id: job['args'][0],
          request_transition_id: job['args'][1]
        )
      end

      def perform(rollout_id, request_transition_id, result, current_user_id)
        rollout = ::Cd::Rollout.find_by_id(rollout_id)
        request_transition = ::Cd::RolloutTransition.find_by_id(request_transition_id)
        current_user = ::User.find_by_id(current_user_id)

        unless rollout && request_transition && current_user
          ::Cd::Logger.info(
            message: 'Skipping rollout gate decision push: rollout, transition, or user no longer exists',
            rollout_id: rollout_id,
            request_transition_id: request_transition_id,
            Labkit::Fields::GL_USER_ID => current_user_id
          )

          return
        end

        ::Cd::Rollouts::PushGateDecisionService.new(
          rollout, request_transition: request_transition, result: result, current_user: current_user
        ).execute
      end
    end
  end
end
