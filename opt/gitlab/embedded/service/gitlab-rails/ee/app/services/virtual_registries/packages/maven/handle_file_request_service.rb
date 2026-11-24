# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class HandleFileRequestService < ::VirtualRegistries::BaseService
        include Gitlab::InternalEventsTracking

        DIGEST_EXTENSIONS = %w[.sha1 .md5].freeze
        PERMISSIONS_CACHE_TTL = 5.minutes

        ERRORS = BASE_ERRORS.merge(
          unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
          no_upstreams: ServiceResponse.error(message: 'No upstreams set', reason: :no_upstreams),
          fips_unsupported_md5: ServiceResponse.error(
            message: 'MD5 digest is not supported when FIPS is enabled',
            reason: :fips_unsupported_md5
          ),
          upstream_not_available: ServiceResponse.error(
            message: 'Upstream not available',
            reason: :upstream_not_available
          ),
          all_upstreams_denied: ServiceResponse.error(
            message: 'All upstreams are filtered out because of existing allow/deny rules',
            reason: :all_upstreams_denied
          )
        ).freeze

        def execute
          return ERRORS[:path_not_present] unless path.present?
          return ERRORS[:unauthorized] unless allowed?
          return ERRORS[:no_upstreams] if registry.all_upstreams.empty?

          # Maven digest request handling
          return handle_digest_request if digest_request?

          # regular request handling
          if cache_response_still_valid?
            download_cache_entry
          else
            create_cache_entry
          end

        rescue *::Gitlab::HTTP::HTTP_ERRORS
          return download_cache_entry if cache_entry

          ERRORS[:upstream_not_available]
        end

        private

        def cache_response_still_valid?
          return false unless cache_entry
          return true unless cache_entry.stale?

          if cache_entry.remote?
            # cache entry with no etag can't be checked
            return false if cache_entry.upstream_etag.blank?

            response = head_remote_upstream(upstream: cache_entry.upstream)

            return false unless cache_entry.upstream_etag == response.headers['etag']
          else
            response = check_local_upstream(upstream: cache_entry.upstream)

            return false unless response.success?
            return false unless cache_entry.package_file_id == response[:local_file].raw_file_id
          end

          cache_entry.update_column(:upstream_checked_at, Time.current)
          true
        end

        def cache_entry
          [
            [VirtualRegistries::Packages::Maven::Cache::Remote::Entry.default, registry.upstreams],
            [VirtualRegistries::Packages::Maven::Cache::Local::Entry.preload_package_file, registry.local_upstreams]
          ].lazy.filter_map do |scope, upstreams|
            scope.for_group(registry.group).for_upstream(upstreams).find_by_relative_path(relative_path)
          end.first
        end
        strong_memoize_attr :cache_entry

        def create_cache_entry
          return check_registry_upstreams_response unless upstream

          if upstream.local?
            local_file = check_registry_upstreams_response[:local_file]

            enqueue_create_cache_local_entry_job(local_file.global_id)
            create_event(from_upstream: false)

            download_file_response(
              file: local_file.file,
              content_type: local_file.content_type,
              file_sha1: local_file.sha1,
              file_md5: local_file.md5
            )
          else
            workhorse_upload_url_response(upstream: upstream)
          end
        end

        def check_registry_upstreams_response
          if registry.all_upstreams.any?(&:remote?)
            return filtration_result if filtration_result.error?

            log_filtration_audit_events

            # Maintain position ordering: include allowed remotes + all locals (no rules for locals)
            ordered = registry.all_upstreams.select do |u|
              u.local? || filtration_result[:allowed_upstreams].include?(u)
            end
          else
            ordered = registry.all_upstreams
          end

          return ERRORS[:all_upstreams_denied] if ordered.empty?

          ::VirtualRegistries::Upstreams::CheckService.new(
            upstreams: ordered,
            params: { path: base_file_path }
          ).execute
        end
        strong_memoize_attr :check_registry_upstreams_response

        def upstream
          return unless check_registry_upstreams_response.success?

          check_registry_upstreams_response[:upstream]
        end

        def head_remote_upstream(upstream:)
          ::VirtualRegistries::Upstreams::Remote::CredentialSafeHeadRequest.head(
            url: upstream.url_for(path),
            headers: upstream.headers,
            timeout: NETWORK_TIMEOUT
          )
        end

        def check_local_upstream(upstream:)
          ::VirtualRegistries::Upstreams::CheckService.new(
            upstreams: [upstream],
            params: { path: base_file_path }
          ).execute
        end

        def handle_digest_request
          format = File.extname(path)[1..] # file extension without the leading dot
          return ERRORS[:fips_unsupported_md5] if format == 'md5' && Gitlab::FIPS.enabled?

          if cache_entry
            # cache entry found. Return the digest from it.
            download_digest(digest: file_digest(cache_entry, format))
          elsif upstream
            # upstream with the requested file found. Send the digest
            # from it and enqueue a create cache entry job.
            if upstream.remote?
              enqueue_create_cache_entry_job

              workhorse_send_url_response(upstream: upstream)
            else
              local_file = check_registry_upstreams_response[:local_file]
              enqueue_create_cache_local_entry_job(local_file.global_id)

              download_digest(digest: local_file.digests[format.to_sym])
            end
          else
            # requested file not found anywhere.
            check_registry_upstreams_response
          end
        end

        def file_digest(entry, format)
          format == 'sha1' ? entry.file_sha1 : entry.file_md5
        end

        def digest_request?
          File.extname(path).in?(DIGEST_EXTENSIONS)
        end
        strong_memoize_attr :digest_request?

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
            'maven',
            registry.id
          ]
        end

        def path
          params[:path]
        end

        def base_file_path
          if digest_request?
            path.chomp(File.extname(path))
          else
            path
          end
        end

        def relative_path
          "/#{base_file_path}"
        end

        def filtration_result
          ::VirtualRegistries::Packages::Maven::Upstreams::FiltrationService.new(
            upstreams: registry.upstreams,
            relative_path: base_file_path
          ).execute
        end
        strong_memoize_attr :filtration_result

        def download_cache_entry
          create_event(from_upstream: false)
          cache_entry.try(:bump_downloads_count)

          download_file_response(
            file: cache_entry.file,
            content_type: cache_entry.content_type,
            file_sha1: cache_entry.file_sha1,
            file_md5: cache_entry.file_md5
          )
        end

        def download_digest(digest:)
          create_event(from_upstream: false)
          cache_entry.try(:bump_downloads_count)

          ServiceResponse.success(
            payload: {
              action: :download_digest,
              action_params: { digest: }
            }
          )
        end

        def download_file_response(file:, content_type:, file_sha1: nil, file_md5: nil)
          ServiceResponse.success(
            payload: {
              action: :download_file,
              action_params: {
                file:,
                file_sha1:,
                file_md5:,
                content_type:
              }.compact
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

        def workhorse_send_url_response(upstream:)
          create_event(from_upstream: true)

          ServiceResponse.success(
            payload: {
              action: :workhorse_send_url,
              action_params: { url: upstream.url_for(path) }
            }
          )
        end

        def create_event(from_upstream:)
          args = {
            namespace: registry.group,
            additional_properties: { label: from_upstream ? 'from_upstream' : 'from_cache' }
          }
          args[:user] = current_user if current_user.is_a?(User)
          track_internal_event('pull_maven_package_file_through_virtual_registry', **args)
        end

        def log_filtration_audit_events
          denied = filtration_result[:denied_upstreams]
          return if denied.blank?

          denied.each do |denied_upstream|
            audit_context = {
              name: 'virtual_registries_packages_maven_upstream_artifact_denied',
              author: current_user,
              scope: registry.group,
              target: denied_upstream,
              target_details: denied_upstream.url_for(base_file_path),
              # TODO: consider adding a link to the UI showing matching allow/deny patterns
              message: 'Blocked package request - View matching patterns'
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e, audit_context.slice(:name, :scope, :target))
          end
        end

        def enqueue_create_cache_entry_job
          ::VirtualRegistries::Packages::Maven::CreateCacheEntryWorker.perform_async(
            upstream.id, base_file_path
          )
        end

        def enqueue_create_cache_local_entry_job(local_file_global_id)
          parsed_global_id = GlobalID.parse(local_file_global_id)

          return unless parsed_global_id
          return unless parsed_global_id.model_class == ::Packages::PackageFile

          ::VirtualRegistries::Packages::Maven::Local::CreateCacheEntryWorker.perform_async(
            upstream.id, parsed_global_id.model_id, relative_path
          )
        end
      end
    end
  end
end
