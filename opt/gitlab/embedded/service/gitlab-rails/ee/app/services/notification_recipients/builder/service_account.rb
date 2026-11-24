# frozen_string_literal: true

module NotificationRecipients # rubocop:disable Gitlab/BoundedContexts -- Existing module structure
  module Builder
    class ServiceAccount < Base
      attr_reader :project, :current_user, :pipeline_status

      def initialize(project, current_user, pipeline_status)
        @project = project
        @current_user = current_user
        @pipeline_status = pipeline_status
      end

      def build!
        add_custom_notifications
      end

      def target; end

      def custom_action
        @custom_action ||= :"service_account_#{pipeline_status}_pipeline"
      end
    end
  end
end
