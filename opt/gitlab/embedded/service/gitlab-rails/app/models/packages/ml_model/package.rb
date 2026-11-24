# frozen_string_literal: true

module Packages
  module MlModel
    class Package < Packages::Package
      self.allow_legacy_sti_class = true

      after_create_commit :publish_creation_event

      has_one :model_version, class_name: "Ml::ModelVersion", inverse_of: :package

      scope :orphaned, -> do
        files = ::Packages::PackageFile.arel_table
        versions = ::Ml::ModelVersion.arel_table

        pending_destruction
          .where_not_exists(::Packages::PackageFile.where(files[:package_id].eq(arel_table[:id])))
          .where_not_exists(::Ml::ModelVersion.where(versions[:package_id].eq(arel_table[:id])))
      end

      # Call inside a transaction: the row locks last until it ends.
      def self.lock_orphaned_ids(ids, limit)
        orphaned.id_in(ids).lock('FOR UPDATE SKIP LOCKED').limit(limit).pluck(:id)
      end

      validates :name,
        format: Gitlab::Regex.ml_model_name_regex,
        presence: true,
        length: { maximum: 255 }

      validates :version,
        format: Gitlab::Regex.ml_model_version_name_regex,
        presence: true,
        length: { maximum: 255 }
    end
  end
end
