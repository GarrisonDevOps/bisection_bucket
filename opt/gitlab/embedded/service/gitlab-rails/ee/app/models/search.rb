# frozen_string_literal: true

module Search
  INDEX_PARTITIONING_HASHING_MODULO = 1024
  DEFAULT_CONCURRENCY_LIMIT = 500
  ORGANIZATION_TRAVERSAL_IDS_SEPARATOR = '/'

  def self.table_name_prefix
    'search_'
  end

  def self.hash_namespace_id(namespace_id, maximum: INDEX_PARTITIONING_HASHING_MODULO)
    return unless namespace_id.present?

    namespace_id.to_s.hash % maximum
  end

  # Builds the `organization_traversal_ids` value indexed alongside `traversal_ids`,
  # for example `24/9970-123-456-`. Namespace ids are only unique within an
  # organization, so a prefix query over `traversal_ids` alone can match a namespace
  # that belongs to a different organization.
  def self.organization_traversal_ids(organization_id, traversal_ids)
    return if organization_id.blank? || traversal_ids.blank?

    "#{organization_id}#{ORGANIZATION_TRAVERSAL_IDS_SEPARATOR}#{traversal_ids}"
  end

  def self.default_concurrency_limit
    DEFAULT_CONCURRENCY_LIMIT
  end
end
