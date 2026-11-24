# frozen_string_literal: true

module VirtualRegistries
  module Container
    module Cache
      module Entries
        class CreateOrUpdateService < BaseCreateOrUpdateCacheEntriesService
          extend ::Gitlab::Utils::Override
          include ::Gitlab::ExclusiveLeaseHelpers

          # Rack::Timeout ends the request after 60 seconds by default, well inside the lease.
          LEASE_TTL = 2.minutes

          ENTRY_REMOVED_ERROR = ServiceResponse.error(
            message: 'Cache entry was removed during the refetch', reason: :cache_entry_removed
          ).freeze

          override :entry_class
          def entry_class
            ::VirtualRegistries::Container::Cache::Remote::Entry
          end

          private

          override :skip_md5?
          def skip_md5?
            true
          end

          override :existing_entry_response
          def existing_entry_response
            if deduplicatable_request? && existing_cache_entry_by_digest
              if Feature.enabled?(:container_virtual_registry_cache_revalidation_fixes, upstream.group)
                # Digest-addressed content never changes, so the entry is as fresh as the upload.
                # A tag entry with this digest is not: the tag may point elsewhere upstream now.
                if existing_cache_entry_by_digest.digest_addressed?
                  existing_cache_entry_by_digest.update_column(:upstream_checked_at, Time.current)
                end

                delete_unused_upload
              end

              existing_cache_entry_by_digest.bump_downloads_count
              return ServiceResponse.success(payload: { cache_entry: existing_cache_entry_by_digest })
            end

            return unless temp_upload?

            in_lock(lease_key, ttl: LEASE_TTL, retries: 0) do
              # Look up under the lease: the entry can be removed while Workhorse streams the upload.
              existing_entry = upstream.default_cache_entries.find_by_relative_path(relative_path)
              next ENTRY_REMOVED_ERROR unless existing_entry

              refetch(existing_entry)
            end
          rescue FailedToObtainLockError
            # Another refetch of the same file holds the lease and writes the same bytes.
            Gitlab::AppJsonLogger.info(
              message: 'Skipped concurrent container virtual registry cache entry refetch',
              group_id: upstream.group_id,
              upstream_id: upstream.id
            )
            ServiceResponse.success
          end

          # A refetch gets a temp upload. A first fetch gets a final-path upload, which has a pending direct upload.
          # Authorize gates temp uploads on the flag, so this doesn't: create_or_update_by! can't store one.
          def temp_upload?
            return false unless file.remote_id.present?

            !::ObjectStorage::PendingDirectUpload.exists?( # rubocop:disable CodeReuse/ActiveRecord -- Redis lookup, not ActiveRecord
              ::VirtualRegistries::Cache::EntryUploader.storage_location_identifier,
              file.remote_id
            )
          end

          # Validate the new row before the copy, and save it right after, so no transaction is open during the copy.
          def refetch(existing_entry)
            copy_needed = !same_remote_bytes?(existing_entry)
            # An entry in local storage moves to object storage, where the copy put the new bytes.
            existing_entry.assign_attributes(
              entry_updates.except(:file).merge(file_store: ::ObjectStorage::Store::REMOTE)
            )
            existing_entry.validate!

            # Accepted behind container_virtual_registry_refetch_overwrite: a copy that raises after the store
            # finished, or a Rack::Timeout (not a StandardError), leaves new bytes with the old row until a refetch.
            copy_upload_to(existing_entry) if copy_needed
            save_after_copy(existing_entry, copied: copy_needed)
            existing_entry.bump_downloads_count

            ServiceResponse.success(payload: { cache_entry: existing_entry })
          end

          # The object now holds the new bytes. If the row can't match them, take the entry out of
          # the cache, so the next pull refetches instead of serving new bytes with old digest headers.
          def save_after_copy(existing_entry, copied:)
            # refetch already validated, and the uniqueness checks scan every partition.
            existing_entry.save!(validate: false)
          rescue StandardError
            existing_entry.update_column(:status, :pending_destruction) if copied
            raise
          end

          # The client waits for this request, so don't copy bytes the entry already serves.
          def same_remote_bytes?(existing_entry)
            existing_entry.file_store == ::ObjectStorage::Store::REMOTE &&
              existing_entry.file_sha1 == file.sha1 &&
              existing_entry.size == file.size
          end

          def copy_upload_to(existing_entry)
            # The entry's object storage key, even for an entry in local storage.
            target_path = ::VirtualRegistries::Cache::EntryUploader.with_bucket_prefix(existing_entry.object_storage_key)
            # A separate uploader, so the entry's mounted uploader never points at the upload.
            uploader = ::VirtualRegistries::Cache::EntryUploader.new(existing_entry, :file)
            uploader.cache!(file)
            start = ::Gitlab::Metrics::System.monotonic_time
            uploader.file.copy_to(target_path)

            Gitlab::AppJsonLogger.info(
              message: 'Copied refetched container virtual registry cache entry',
              group_id: existing_entry.group_id,
              upstream_id: upstream.id,
              size: file.size,
              duration_s: (::Gitlab::Metrics::System.monotonic_time - start).round(3)
            )
          end

          def lease_key
            "virtual_registries:container:cache_entry:#{upstream.id}:#{Digest::SHA256.hexdigest(relative_path)}"
          end

          # Workhorse uploaded to a new final path that no entry references, and authorize registered it
          # as a pending direct upload. Delete both, or they wait for the stale upload cleanup.
          def delete_unused_upload
            location = ::VirtualRegistries::Cache::EntryUploader.storage_location_identifier
            path = file.remote_id
            return if path.blank? || !::ObjectStorage::PendingDirectUpload.exists?(location, path) # rubocop:disable CodeReuse/ActiveRecord -- Redis lookup, not ActiveRecord

            ::ObjectStorage::PendingDirectUpload.new(
              redis_key: ::ObjectStorage::PendingDirectUpload.redis_key(location, path),
              storage_location_identifier: location,
              object_storage_path: path,
              timestamp: Time.current.to_i
            ).delete
          rescue StandardError => error
            # The pull already succeeded; the stale upload cleanup removes what is left.
            Gitlab::ErrorTracking.track_exception(
              error,
              upstream_id: upstream.id,
              group_id: upstream.group_id,
              class: self.class.name
            )
          end

          override :customize_updates
          def customize_updates(updates)
            updates[:digest] = digest if digest.present?
          end

          def digest
            VirtualRegistries::Container.extract_digest_from_path(path) ||
              manifest_content_digest ||
              extract_digest_from_etag(etag)
          end
          strong_memoize_attr :digest

          # Some upstreams (e.g. quay.io) send no ETag, or one that isn't the digest.
          # A manifest's digest is the sha256 of its bytes, which Workhorse computes on upload.
          def manifest_content_digest
            return unless path.include?('/manifests/') && file.sha256.present?

            "sha256:#{file.sha256}"
          end

          def extract_digest_from_etag(value)
            return if value.blank?

            value if value.match?(VirtualRegistries::Container::OCI_DIGEST_VALIDATION_REGEX)
          end

          def deduplicatable_request?
            path.include?('/blobs/') || manifest_digest_request?
          end

          def manifest_digest_request?
            path.include?('/manifests/') &&
              VirtualRegistries::Container.extract_digest_from_path(path).present?
          end

          def existing_cache_entry_by_digest
            return unless digest.present?

            ::VirtualRegistries::Container::Cache::Remote::Entry
              .default
              .for_upstream(upstream)
              .for_group(upstream.group)
              .for_digest(digest)
              .first
          end
          strong_memoize_attr :existing_cache_entry_by_digest
        end
      end
    end
  end
end
