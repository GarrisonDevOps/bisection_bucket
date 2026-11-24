# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Npm
      class HandleFileRequestService < ::VirtualRegistries::BaseService
        include Gitlab::InternalEventsTracking

        NOT_MODIFIED = 304

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
          if cache_entry
            download_cache_entry
          else
            ERRORS[:upstream_not_available]
          end
        end

        private

        def cache_response_still_valid?
          return false unless cache_entry
          return true unless cache_entry.stale?
          return false if cache_entry.upstream_etag.blank?

          response = head_upstream(upstream: cache_entry.upstream)

          if response.code == NOT_MODIFIED
            cache_entry.update_column(:upstream_checked_at, Time.current)
            return true
          end

          return false unless response.success?
          return false unless cache_entry.upstream_etag == response.headers['etag']

          cache_entry.update_column(:upstream_checked_at, Time.current)
          true
        end

        def cache_entry
          VirtualRegistries::Packages::Npm::Cache::Remote::Entry
            .default
            .for_group(registry.group)
            .for_upstream(registry.upstreams)
            .find_by_relative_path(relative_path)
        end
        strong_memoize_attr :cache_entry

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
          headers = upstream.headers
          headers['If-None-Match'] = cache_entry.upstream_etag

          ::VirtualRegistries::Upstreams::Remote::CredentialSafeHeadRequest.head(
            url: upstream.url_for(path),
            headers: headers,
            timeout: NETWORK_TIMEOUT
          )
        end

        def allowed?
          return false unless current_user

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
            'npm',
            registry.id
          ]
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
                file_md5: cache_entry.file_md5,
                content_type: cache_entry.content_type
              }
            }
          )
        end

        def workhorse_upload_url_response(upstream:)
          create_event(from_upstream: true)

          ServiceResponse.success(
            payload: {
              action: :workhorse_upload_url,
              action_params: { url: upstream.url_for(path), upstream: upstream }
            }
          )
        end

        def create_event(from_upstream:)
          args = {
            namespace: registry.group,
            additional_properties: { label: from_upstream ? 'from_upstream' : 'from_cache' }
          }
          args[:user] = current_user if current_user.is_a?(User)
          track_internal_event('pull_npm_package_file_through_virtual_registry', **args)
        end
      end
    end
  end
end
