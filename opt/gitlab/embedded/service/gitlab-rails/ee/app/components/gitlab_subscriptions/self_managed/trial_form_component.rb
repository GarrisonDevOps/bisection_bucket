# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class TrialFormComponent < ViewComponent::Base
      def initialize(**kwargs)
        @user = kwargs[:user]
      end

      private

      attr_reader :user

      def before_render
        content_for :body_class, '!gl-bg-default'
      end

      def form_data
        ::Gitlab::Json.generate(
          {
            userData: user_data,
            submitPath: submit_path
          }
        )
      end

      def user_data
        {
          firstName: user.first_name,
          lastName: user.last_name,
          emailAddress: user.email
        }
      end

      def submit_path
        self_managed_trials_path
      end
    end
  end
end
