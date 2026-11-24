# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class ResubmitComponent < Trials::ResubmitComponent
      extend ::Gitlab::Utils::Override

      private

      override :top_page_component
      def top_page_component
        GitlabSubscriptions::SelfManaged::TopPageComponent
      end

      override :resubmit_button_data
      def resubmit_button_data
        { event_tracking: 'sm_trial_create_form_resubmit_click' }
      end
    end
  end
end
