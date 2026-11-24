# frozen_string_literal: true

module EE
  module API
    module Helpers
      module RunnerControllerHelpers
        include ::Gitlab::Utils::StrongMemoize

        def runner_controller
          runner_controller_token&.runner_controller
        end

        def runner_controller_token
          runner_controller_token_from_authorization_token
        end
        strong_memoize_attr :runner_controller_token

        def check_runner_controller_token!
          unauthorized! unless runner_controller_token

          ::Ci::RunnerControllers::TrackTokenUsageService.new(runner_controller_token).execute
        end
      end
    end
  end
end
