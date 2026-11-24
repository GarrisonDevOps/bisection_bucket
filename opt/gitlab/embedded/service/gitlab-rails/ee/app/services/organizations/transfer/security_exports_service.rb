# frozen_string_literal: true

module Organizations
  module Transfer
    class SecurityExportsService
      include Organizations::Transfer::Concerns::OrganizationUpdater
      include Organizations::Transfer::Concerns::MissingRecordHandling

      def initialize(group:, old_organization:, new_organization:)
        @group = group
        @old_organization = old_organization
        @new_organization = new_organization
      end

      def execute
        error = missing_record_error
        return error if error

        ::SecApplicationRecord.transaction do
          each_group_batch do |batch|
            transfer_exports_for { |relation| relation.for_group(batch) }
          end

          each_project_batch do |batch|
            transfer_exports_for { |relation| relation.for_project(batch) }
          end
        end

        ServiceResponse.success
      end

      private

      attr_reader :group, :old_organization, :new_organization

      # The block applies the same group or project scope to every export model.
      def transfer_exports_for(&scope)
        update_organization_id_for(::Vulnerabilities::Export, &scope)

        each_export_batch(yield(::Dependencies::DependencyListExport)) do |export_ids|
          update_organization_id_for(::Dependencies::DependencyListExport::Part) do |relation|
            relation.for_exports(export_ids)
          end
        end

        each_export_batch(yield(::Vulnerabilities::Export)) do |export_ids|
          update_organization_id_for(::Vulnerabilities::Export::Part) do |relation|
            relation.for_exports(export_ids)
          end
        end
      end

      def each_export_batch(exports)
        exports.each_batch(of: ApplicationRecord::MAX_PLUCK) do |batch|
          yield batch.limit(ApplicationRecord::MAX_PLUCK).pluck_primary_key
        end
      end

      # Batching because of cross-db queries
      def each_group_batch
        group.self_and_descendant_ids.each_batch(of: ApplicationRecord::MAX_PLUCK) do |batch|
          yield batch.limit(ApplicationRecord::MAX_PLUCK).pluck_primary_key
        end
      end

      # Batching because of cross-db queries
      def each_project_batch
        ::Project.in_namespace(group.self_and_descendant_ids(skope: ::Namespace))
          .each_batch(of: ApplicationRecord::MAX_PLUCK) do |batch|
          yield batch.limit(ApplicationRecord::MAX_PLUCK).pluck_primary_key
        end
      end
    end
  end
end
