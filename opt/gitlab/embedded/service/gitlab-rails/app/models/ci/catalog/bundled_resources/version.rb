# frozen_string_literal: true

module Ci
  module Catalog
    module BundledResources
      class Version < ::ApplicationRecord
        include CacheMarkdownField
        include SemanticVersionable

        self.table_name = 'catalog_bundled_resource_versions'

        ignore_columns :file_store, remove_with: '19.7', remove_after: '2026-11-14'

        belongs_to :bundled_resource, class_name: 'Ci::Catalog::BundledResource',
          foreign_key: :catalog_bundled_resource_id, inverse_of: :versions, optional: false
        has_many :components, class_name: 'Ci::Catalog::BundledResources::Component',
          foreign_key: :catalog_bundled_version_id, inverse_of: :version

        cache_markdown_field :readme, storage: :external
        mount_external_storage ::Ci::Catalog::BundledResources::ReadmeUploader

        validates :semver_prerelease, length: { maximum: 255 }

        scope :for_bundled_resources, ->(bundled_resource_ids) {
          where(catalog_bundled_resource_id: bundled_resource_ids)
        }
        scope :with_semver, -> { where.not(semver_major: nil) }
        scope :without_prerelease, -> { where(semver_prerelease: nil) }

        class << self
          def latest(major = nil, minor = nil)
            raise ArgumentError, 'semver minor version used without major version' if minor.present? &&
              major.blank?

            relation = with_semver.without_prerelease
            relation = relation.where(semver_major: major) if major
            relation = relation.where(semver_minor: minor) if minor

            relation.order_by_semantic_version_desc.first
          end
        end
      end
    end
  end
end
