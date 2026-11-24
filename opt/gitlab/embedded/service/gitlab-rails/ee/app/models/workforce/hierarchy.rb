# frozen_string_literal: true

module Workforce
  class Hierarchy < ApplicationRecord
    self.table_name = 'workforce_hierarchies'

    # Nullable until the Workday integration lands in
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/629838, which makes it required.
    belongs_to :integration, optional: true
    belongs_to :group, optional: true
    belongs_to :organization, class_name: 'Organizations::Organization', optional: true

    has_many :people, class_name: 'Workforce::Person', foreign_key: :workforce_hierarchy_id, inverse_of: :hierarchy

    # Written by the sync in https://gitlab.com/gitlab-org/gitlab/-/work_items/629840.
    enum :last_sync_status, { never_run: 0, success: 1, failed: 2 }, prefix: true

    validates_with ExactlyOnePresentValidator, fields: %i[group_id organization_id]
    # The tenant on GitLab.com is the root group.
    validates :group, top_level_group: true

    # Called by the group and organization destroy services, so a tenant with tens of thousands
    # of people is not deleted by a single foreign key cascade.
    def self.delete_for_tenant(group: nil, organization: nil)
      batch_size = BatchDeleteDependentAssociations::DEPENDENT_ASSOCIATIONS_BATCH_SIZE

      where(group: group, organization: organization).find_each do |hierarchy|
        loop do
          break if Workforce::Person.in_hierarchy(hierarchy).limit(batch_size).delete_all < batch_size
        end

        hierarchy.delete
      end
    end
  end
end
