# frozen_string_literal: true

module EE
  module Repositories
    module LfsApiController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override
      include GitlabRoutingHelper
      include ::Gitlab::Utils::StrongMemoize

      override :batch_operation_disallowed?
      def batch_operation_disallowed?
        super_result = super
        return true if super_result && !::Gitlab::Geo.enabled?

        if super_result && ::Gitlab::Geo.enabled?
          return true if !::Gitlab::Geo.primary? && !::Gitlab::Geo.secondary?
          return true if ::Gitlab::Geo.secondary? && !::Gitlab::Geo.primary_node_configured?
        end

        false
      end

      override :upload_http_url_to_repo
      def upload_http_url_to_repo
        return geo_primary_http_url_to_repo(repository) if ::Gitlab::Geo.primary?

        super
      end

      override :lfs_read_only_message
      def lfs_read_only_message
        return super unless ::Gitlab::Geo.secondary_with_primary?

        translation = _('You cannot write to a read-only secondary GitLab Geo instance. Please use %{link_to_primary_node} instead.')
        message = format(translation, link_to_primary_node: geo_primary_default_url_to_repo(project))
        message.html_safe
      end

      def proxy_download_actions_download_path(object)
        # This logic guarantees the download from the primary when unified URL is enabled
        # Without it, the download links might send a redirected request back to a secondary
        # https://gitlab.com/gitlab-org/gitlab/-/issues/543956
        if request.fullpath.include?(::Gitlab::Geo::GitPushHttp::PATH_PREFIX) && geo_referrer_secondary_node_id
          uri = URI.parse(project.http_url_to_repo)
          return File.join(uri.origin, geo_referrer_path_prefix, uri.path, "gitlab-lfs/objects/#{object[:oid]}")
        end

        super
      end

      private

      def geo_referrer_secondary_node_id
        id = params.permit(:geo_node_id)[:geo_node_id]
        return id if id && ::Gitlab::Geo.secondary_node?(id)

        ::Gitlab::Geo::Logger.warn(message: "proxy_download_actions: Secondary Geo node not found", geo_node_id: id)
      end
      strong_memoize_attr :geo_referrer_secondary_node_id

      def geo_referrer_path_prefix
        File.join(::Gitlab::Geo::GitPushHttp::PATH_PREFIX, geo_referrer_secondary_node_id)
      end
    end
  end
end
