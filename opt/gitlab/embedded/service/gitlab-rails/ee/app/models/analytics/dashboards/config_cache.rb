# frozen_string_literal: true

module Analytics
  module Dashboards
    # Caches the dashboard and visualization YAML read from a configuration project so
    # repeat requests do not reach Gitaly. The key carries the head commit sha, so a push
    # invalidates it; the TTL is a safety net in case the key ever misses a change.
    class ConfigCache
      EXPIRES_IN = 5.minutes
      KEY_PREFIX = 'analytics_dashboards_config'

      class << self
        def fetch(config_project, *name, &block)
          return yield unless enabled?(config_project)

          Rails.cache.fetch(key(config_project, name), expires_in: EXPIRES_IN, skip_nil: true, &block)
        end

        def blob_data_at(config_project, path)
          blobs_data_at(config_project, [path])[path]
        end

        # Returns { path => data } in the order of `paths`. Misses are read from the
        # repository and written back only when the file is small enough to be parsed.
        def blobs_data_at(config_project, paths)
          paths = paths.uniq
          return paths.index_with { |path| read_blob(config_project, path) } unless enabled?(config_project)

          keys = paths.index_with { |path| key(config_project, [:blob, path]) }
          cached = Rails.cache.read_multi(*keys.values)
          writes = {}

          blobs = paths.index_with do |path|
            cached.fetch(keys[path]) do
              data = read_blob(config_project, path)
              writes[keys[path]] = data if cacheable?(data)
              data
            end
          end

          Rails.cache.write_multi(writes, expires_in: EXPIRES_IN) if writes.any?

          blobs
        end

        private

        def enabled?(config_project)
          Feature.enabled?(:customizable_dashboards_config_cache, config_project) &&
            !config_project.repository.empty?
        end

        def key(config_project, name)
          [KEY_PREFIX, config_project.id, config_project.repository.root_ref_sha, *name]
        end

        # Anything larger raises DataTooLargeError when parsed, so caching it would only
        # fill Redis with content no request can use.
        def cacheable?(data)
          data.present? && data.bytesize <= Gitlab::CurrentSettings.max_yaml_size_bytes
        end

        # An empty repository has no head commit, so callers need not check it themselves.
        def read_blob(config_project, path)
          repository = config_project.repository
          return if repository.empty?

          repository.blob_data_at(repository.root_ref_sha, path)
        end
      end
    end
  end
end
