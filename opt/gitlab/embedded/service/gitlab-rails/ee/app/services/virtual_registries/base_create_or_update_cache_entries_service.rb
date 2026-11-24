# frozen_string_literal: true

module VirtualRegistries
  class BaseCreateOrUpdateCacheEntriesService < ::BaseContainerService
    alias_method :upstream, :container

    ERRORS = {
      unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized),
      path_not_present: ServiceResponse.error(message: 'Parameter path not present', reason: :path_not_present),
      file_not_present: ServiceResponse.error(message: 'Parameter file not present', reason: :file_not_present),
      file_empty: ServiceResponse.error(message: 'File is empty', reason: :file_empty)
    }.freeze

    def initialize(upstream:, current_user: nil, params: {})
      super(container: upstream, current_user: current_user, params: params)
    end

    def execute
      return ERRORS[:path_not_present] unless path.present?
      return ERRORS[:file_not_present] unless file.present?
      return ERRORS[:file_empty] if file.empty_size?
      return ERRORS[:unauthorized] unless allowed?

      response = existing_entry_response
      return response if response

      cache_remote_entry = entry_class.create_or_update_by!(
        group_id: upstream.group_id,
        upstream: upstream,
        relative_path: relative_path,
        updates: entry_updates
      )

      cache_remote_entry.bump_downloads_count

      ServiceResponse.success(payload: { cache_entry: cache_remote_entry })
    rescue StandardError => error
      Gitlab::ErrorTracking.track_exception(
        error,
        upstream_id: upstream.id,
        group_id: upstream.group_id,
        class: self.class.name
      )
      ServiceResponse.error(message: error.message, reason: :persistence_error)
    end

    def entry_class
      raise NotImplementedError, "#{self.class} must implement entry_class"
    end

    private

    def skip_md5?
      false
    end

    def existing_entry_response
      nil
    end

    def entry_updates
      updates = {
        upstream_etag: etag,
        upstream_checked_at: Time.zone.now,
        file: file,
        size: file.size,
        file_sha1: file.sha1,
        content_type: content_type
      }.compact_blank

      updates[:file_md5] = file.md5 if !skip_md5? && !Gitlab::FIPS.enabled?

      customize_updates(updates)
      updates
    end

    def customize_updates(updates); end

    def allowed?
      return true if skip_permission_check

      can?(current_user, :read_virtual_registry, upstream)
    end

    def file
      params[:file]
    end

    def path
      params[:path]
    end

    def relative_path
      "/#{path}"
    end

    def etag
      params[:etag]
    end

    def content_type
      params[:content_type]
    end

    def skip_permission_check
      !!params[:skip_permission_check]
    end
  end
end
