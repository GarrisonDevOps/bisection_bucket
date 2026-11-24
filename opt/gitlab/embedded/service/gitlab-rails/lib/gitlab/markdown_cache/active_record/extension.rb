# frozen_string_literal: true

module Gitlab
  module MarkdownCache
    module ActiveRecord
      module Extension
        extend ActiveSupport::Concern

        included do
          # Using before_update here conflicts with elasticsearch-model somehow
          before_create :refresh_markdown_cache, if: :invalidated_markdown_cache?
          before_update :refresh_markdown_cache, if: :invalidated_markdown_cache?
          # The import case needs to be fixed to avoid large number of
          # SQL queries: https://gitlab.com/gitlab-org/gitlab/-/issues/21801
          after_save :run_store_mentions!, if: -> { store_mentions? && mentionable_attributes_changed? }, unless: ->(obj) { obj.is_a?(Importable) && obj.importing? }
        end

        def run_store_mentions!
          if store_mentions_after_commit?
            run_after_commit { store_mentions! }
          else
            store_mentions!
          end
        end

        # Always exclude _html fields from attributes (including serialization).
        # They contain unredacted HTML, which would be a security issue
        def attributes
          attrs = super
          html_fields = cached_markdown_fields.html_fields
          whitelisted = cached_markdown_fields.html_fields_whitelisted
          exclude_fields = html_fields - whitelisted

          attrs.except!(*exclude_fields)
          attrs.delete('cached_markdown_version') if whitelisted.empty?

          attrs
        end

        def write_markdown_field(field_name, value)
          write_attribute(field_name, value)
        end

        def markdown_field_changed?(field_name)
          attribute_changed?(field_name)
        end

        def refresh_stale_markdown_cache
          return refresh_markdown_cache! unless markdown_cache_persistable? && refresh_stale_markdown_cache_async?

          if markdown_cache_awaiting_rollout?
            self.latest_cached_markdown_version = cached_markdown_version
          else
            clear_attribute_changes(refresh_markdown_cache.keys)
          end

          Gitlab::MarkdownCache::RefreshBatch.add(self)
        end

        def markdown_cache_current?
          markdown_cache_version_tier == :current && !cached_markdown_html_missing?
        end

        def save_markdown(updates)
          written = ::Gitlab::Database::QueryAnalyzers::PreventWritesOnGet.allow_write_on_get(
            url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/608670') do
            # rubocop:disable CodeReuse/ActiveRecord -- this module is AR-specific; needed here
            self.class.unscoped
              .where(self.class.primary_key => id_in_database)
              .where('COALESCE(cached_markdown_version, 0) <= ?', cached_markdown_version)
              .where(markdown_render_inputs_in_columns)
              .update_all(updates) == 1
            # rubocop:enable CodeReuse/ActiveRecord
          end

          count_version_upgrade if written

          updates.each { |name, value| write_attribute(name, value) }
          clear_attribute_changes(updates.keys)

          written
        end

        private

        def markdown_cache_persistable?
          persisted? && Gitlab::Database.read_write? &&
            cached_markdown_fields.markdown_fields.none? { |field| markdown_inputs_changed?(field) }
        end

        def markdown_cache_awaiting_rollout?
          markdown_cache_version_tier == :previous && !changed? && !cached_markdown_html_missing?
        end

        def refresh_stale_markdown_cache_async?
          Feature.enabled?(:markdown_cache_async_refresh, Feature.current_request)
        end

        def markdown_render_inputs_in_columns
          markdown_render_inputs.index_with { |column| read_attribute(column) }
        end

        def markdown_render_inputs
          fields = cached_markdown_fields.markdown_fields
          sources = fields.select { |field| can_cache_field?(field) }.map(&:to_s)

          (sources + CacheMarkdownField::INVALIDATED_BY).select { |column| self.class.columns_hash.key?(column) } +
            fields.flat_map { |field| markdown_invalidating_columns(field) }
        end

        def markdown_cache_version_tier(version = cached_markdown_version)
          Gitlab::MarkdownCache.version_tier(version, local_version: local_markdown_version_for_cache)
        end

        def count_version_upgrade
          tier = markdown_cache_version_tier(cached_markdown_version_in_database)
          return if tier == :current

          # Concurrent refreshes of the same previous-version row can each pass
          # the guarded update in save_markdown, which allows same-version
          # rewrites, and each compares against its own load-time version, so a
          # single row can be counted more than once. The counter therefore is an
          # upper bound on rows upgraded, not necessarily the exact number.
          Gitlab::MarkdownCache.version_upgrade_counter.increment(
            class: self.class.name,
            kind: tier == :previous ? :rollout : :backfill
          )
        end
      end
    end
  end
end
