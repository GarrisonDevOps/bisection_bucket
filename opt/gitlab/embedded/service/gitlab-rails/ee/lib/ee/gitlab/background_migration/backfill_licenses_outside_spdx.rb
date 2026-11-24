# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillLicensesOutsideSpdx
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          operation_name :backfill_licenses_outside_spdx
          scope_to ->(relation) do
            relation.where.not(software_license_spdx_identifier: nil)
               .where.not(software_license_spdx_identifier: ::Gitlab::SPDX::Catalogue.latest_active_licenses.map(&:id))
          end
        end

        class SoftwareLicensePolicy < ::ApplicationRecord
          self.table_name = 'software_license_policies'
        end

        class CustomSoftwareLicense < ::ApplicationRecord
          self.table_name = 'custom_software_licenses'
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            SoftwareLicensePolicy.id_in(sub_batch).find_each do |software_license_policy|
              non_spdx_license_name = software_license_policy.software_license_spdx_identifier

              custom_software_license = find_or_create_custom_software_license(non_spdx_license_name,
                software_license_policy.project_id)

              next unless custom_software_license

              software_license_policy.update!(custom_software_license_id: custom_software_license.id,
                software_license_spdx_identifier: nil)
            rescue ActiveRecord::RecordNotUnique
              # We have some software_license_policies records with the same software_license_spdx_identifier
              # for the same policy. These records would result in the same custom_software_license
              # violating the constraint "idx_software_license_policies_unique_on_custom_license_project".
              # In this migration we will update one of these records and ignore the duplicated ones.
              # In a follow-up we will delete the duplicated records
              next
            end
          end
        end

        private

        def find_or_create_custom_software_license(name, project_id)
          params = { name: name, project_id: project_id }
          CustomSoftwareLicense.upsert(params, unique_by: [:project_id, :name])
          CustomSoftwareLicense.find_by(params)
        end
      end
    end
  end
end
