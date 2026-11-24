# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class ApplyTrialService
      include ::Gitlab::Utils::StrongMemoize

      GENERIC_TRIAL_ERROR = :generic_trial_error

      def self.execute(args = {})
        instance = new(**args)
        instance.execute
      end

      def initialize(uid:, trial_user_information:)
        @uid = uid
        @trial_user_information = trial_user_information
      end

      def execute
        if valid_to_generate_trial?
          generate_trial
        else
          ServiceResponse.error(message: 'Not valid to generate a trial with current information')
        end
      end

      def generate_trial
        response = execute_trial_request

        if response[:success]
          # We need to stick to an up to date replica or primary db here in order
          # to properly observe the add_on_purchase that CustomersDot created.
          # See https://gitlab.com/gitlab-org/gitlab/-/issues/499720
          Namespace.sticking.find_caught_up_replica(:namespace, namespace.id)

          after_success_hook

          ServiceResponse.success
        else
          ServiceResponse.error(message: response.dig(:data, :errors), reason: GENERIC_TRIAL_ERROR)
        end
      end

      def valid_to_generate_trial?
        namespace.present? && GitlabSubscriptions::Trials.namespace_eligible?(namespace)
      end

      private

      attr_reader :uid, :trial_user_information

      def client
        Gitlab::SubscriptionPortal::Client
      end

      def namespace
        Namespace.find_by_id(trial_user_information[:namespace_id])
      end
      strong_memoize_attr :namespace

      def execute_trial_request
        trial_user_information.merge!(add_on_name: 'duo_enterprise', trial_type: trial_type)

        client.generate_trial(uid: uid, trial_user: trial_user_information)
      end

      def trial_type
        GitlabSubscriptions::Trials.trial_type_for_namespace(namespace)
      end

      def after_success_hook
        clear_dap_access_cache
      end

      def clear_dap_access_cache
        # Clear DAP access caches for the user who started the trial.
        # Other namespace members will get access when their cache expires.
        ::Ai::UserAuthorizer.clear_group_with_ai_available_cache(uid)
      end
    end
  end
end
