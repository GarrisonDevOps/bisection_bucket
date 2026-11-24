# frozen_string_literal: true

module Projects
  module GoogleCloud
    class ArtifactRegistryController < ::Projects::ApplicationController
      layout 'project'

      before_action :authorize_read_google_cloud_artifact_registry!
      before_action :ensure_feature!

      feature_category :container_registry

      # The show action renders index to allow frontend routing to work on page refresh
      def show
        render :index
      end

      private

      def ensure_feature!
        render_404 unless ::Gitlab::Saas.feature_available?(:google_cloud_support)
      end
    end
  end
end
