# frozen_string_literal: true

module EE
  module Projects
    module BlobController
      extend ActiveSupport::Concern

      prepended do
        before_action do
          push_licensed_feature(:remote_development)
          push_frontend_feature_flag(:blame_agent_sessions, @project)
        end

        before_action only: [:show] do
          push_frontend_ability(ability: :read_code_navigation, resource: @project, user: current_user)
        end

        prepend_around_action :repair_blobs_index, only: [:show]
      end

      def visiting_from_search_page?
        return false if request.referer.blank?

        uri = URI.parse request.referer
        query_params = Rack::Utils.parse_query uri.query
        uri.present? && uri.path == search_path && query_params['scope'] == 'blobs'
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)
        false
      end

      def repair_blobs_index
        yield
        return if @blob # We cannot use blob method as that is redirecting us in case of 404.

        return unless visiting_from_search_page?
        # authorize_read_code! runs inside this around_action, so a denied request still reaches here
        return unless current_user && project && can?(current_user, :read_code, project)

        resource_scope = ::Gitlab::ApplicationRateLimiter.parent_scope(project)
        return if ::Gitlab::ApplicationRateLimiter.throttled?(:search_index_blob_repair, scope: resource_scope)

        ::Search::ProjectIndexIntegrityWorker.perform_async(project.id, { force_repair_blobs: true })
      end
    end
  end
end
