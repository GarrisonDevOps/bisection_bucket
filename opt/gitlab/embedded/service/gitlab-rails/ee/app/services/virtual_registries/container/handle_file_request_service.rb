# frozen_string_literal: true

module VirtualRegistries
  module Container
    class HandleFileRequestService < ::VirtualRegistries::BaseService
      include Gitlab::InternalEventsTracking

      PERMISSIONS_CACHE_TTL = 5.minutes

      ERRORS = BASE_ERRORS.merge(
        unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
        no_upstreams: ServiceResponse.error(message: 'No upstreams set', reason: :no_upstreams),
        upstream_not_available: ServiceResponse.error(
          message: 'Upstream not available',
          reason: :upstream_not_available
        )
      ).freeze

      def execute
        return ERRORS[:path_not_present] unless path.present?
        return ERRORS[:unauthorized] unless allowed?
        return ERRORS[:no_upstreams] if registry.upstreams.empty?

        if cache_response_still_valid?
          download_cache_entry
        else
          check_registry_upstreams
        end

      rescue *::Gitlab::HTTP::HTTP_ERRORS
        return download_cache_entry if cache_entry

        ERRORS[:upstream_not_available]
      end

      private

      def cache_response_still_valid?
        return false unless cache_entry
        return true if digest_addressed_request? && !cache_entry.stale?
        return true unless cache_entry.stale?

        return false if cache_entry.upstream_etag.blank?

        response = head_upstream(upstream: cache_entry.upstream)
        upstream_etag = response.headers['etag']
        # The stored ETag has its quotes stripped on upload, but upstreams send it quoted.
        if Feature.enabled?(:container_virtual_registry_cache_revalidation_fixes, registry.group)
          upstream_etag = VirtualRegistries::Container.sanitize_etag(upstream_etag)
        end

        return false unless cache_entry.upstream_etag == upstream_etag

        cache_entry.update_column(:upstream_checked_at, Time.current) if refresh_checked_at?
        true
      end

      # A digest lookup can return a tag entry. A matching digest says nothing about where the tag points now.
      def refresh_checked_at?
        return true unless Feature.enabled?(:container_virtual_registry_cache_revalidation_fixes, registry.group)

        !digest_addressed_request? || cache_entry.digest_addressed?
      end

      def cache_entry
        base_query = build_base_query
        digest = VirtualRegistries::Container.extract_digest_from_path(path)

        if digest
          base_query.for_digest(digest).first
        else
          base_query.find_by_relative_path(relative_path)
        end
      end
      strong_memoize_attr :cache_entry

      def build_base_query
        VirtualRegistries::Container::Cache::Remote::Entry
          .default
          .for_upstream(registry.upstreams)
          .for_group(registry.group)
      end

      def check_registry_upstreams
        service = ::VirtualRegistries::Upstreams::CheckService.new(
          upstreams: registry.upstreams,
          params: { path: path }
        )

        response = service.execute
        return response unless response.success?

        workhorse_upload_url_response(upstream: response.payload[:upstream])
      end

      def head_upstream(upstream:)
        ::VirtualRegistries::Upstreams::Remote::CredentialSafeHeadRequest.head(
          url: upstream.url_for(path),
          headers: upstream.headers(path),
          timeout: NETWORK_TIMEOUT
        )
      end

      def allowed?
        return false unless current_user # anonymous users can't access virtual registries

        Rails.cache.fetch(permissions_cache_key, expires_in: PERMISSIONS_CACHE_TTL) do
          can?(current_user, :read_virtual_registry, registry)
        end
      end

      def permissions_cache_key
        [
          'virtual_registries',
          current_user.model_name.cache_key,
          current_user.id,
          'read_virtual_registry',
          'container',
          registry.id
        ]
      end

      def digest_addressed_request?
        VirtualRegistries::Container.extract_digest_from_path(path).present?
      end

      def path
        params[:path]
      end

      def relative_path
        "/#{path}"
      end

      def download_cache_entry
        create_event(from_upstream: false)
        cache_entry.bump_downloads_count

        ServiceResponse.success(
          payload: {
            action: :download_file,
            action_params: {
              file: cache_entry.file,
              file_sha1: cache_entry.file_sha1,
              content_type: cache_entry.content_type,
              upstream_etag: cache_entry.upstream_etag,
              digest: cache_entry.digest,
              size: cache_entry.size
            }
          }
        )
      end

      def workhorse_upload_url_response(upstream:)
        create_event(from_upstream: true)

        ServiceResponse.success(
          payload: {
            action: :workhorse_upload_url,
            action_params: {
              url: upstream.url_for(path),
              upstream: upstream,
              overwrite: overwrite?(upstream)
            }
          }
        )
      end

      # The refetch writes to the picked upstream's entry, which can differ from the one cache_entry found.
      def overwrite?(upstream)
        return false unless Feature.enabled?(:container_virtual_registry_refetch_overwrite, upstream.group)

        upstream.default_cache_entries.find_by_relative_path(relative_path).present?
      end

      def create_event(from_upstream:)
        args = {
          namespace: registry.group,
          additional_properties: { label: from_upstream ? 'from_upstream' : 'from_cache' }
        }
        args[:user] = current_user if current_user.is_a?(User)
        track_internal_event('pull_container_file_through_virtual_registry', **args)
      end
    end
  end
end
