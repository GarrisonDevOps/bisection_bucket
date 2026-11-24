# frozen_string_literal: true

module Workforce
  class Person < ApplicationRecord
    # Gives `within(traversal_ids)`, the half-open range scan served by
    # index_workforce_people_on_hierarchy_id_and_traversal_ids.
    include Namespaces::Traversal::Traversable

    self.table_name = 'workforce_people'

    belongs_to :hierarchy, class_name: 'Workforce::Hierarchy', foreign_key: :workforce_hierarchy_id,
      inverse_of: :people, optional: false
    # A person outlives the user they were matched to: the foreign key nullifies on delete,
    # and being unmatched is an expected state, not an error. The row is the tenant's HR
    # record, not account data: the sync removes people who leave
    # (https://gitlab.com/gitlab-org/gitlab/-/work_items/629839), and deleting the integration
    # removes all of the tenant's people (https://gitlab.com/gitlab-org/gitlab/-/work_items/629842).
    belongs_to :user, optional: true
    belongs_to :group, optional: true
    belongs_to :organization, class_name: 'Organizations::Organization', optional: true

    populate_sharding_key :group_id, source: :hierarchy
    populate_sharding_key :organization_id, source: :hierarchy

    validates :external_xid, :full_name, presence: true
    validates :external_xid, :manager_external_xid, :full_name, length: { maximum: 255 }
    validates_with ExactlyOnePresentValidator, fields: %i[group_id organization_id]
    # Copied from the hierarchy, whose tenant on GitLab.com is the root group.
    validates :group, top_level_group: true

    # Every read is scoped to one hierarchy: that is what keeps a tenant's people
    # out of another tenant's results, and what lets the composite indexes be used.
    scope :in_hierarchy, ->(hierarchy) { where(workforce_hierarchy_id: hierarchy) }
    scope :subtree_of, ->(person) do
      # A row is inserted before its own id is appended to its path, so the path can briefly be empty.
      next none if person.traversal_ids.empty?

      in_hierarchy(person.workforce_hierarchy_id).within(person.traversal_ids)
    end
    scope :direct_reports_of, ->(person) do
      in_hierarchy(person.workforce_hierarchy_id).where(manager_external_xid: person.external_xid)
    end
    scope :matched, ->(hierarchy) { in_hierarchy(hierarchy).where.not(user_id: nil) }
    scope :unmatched, ->(hierarchy) { in_hierarchy(hierarchy).where(user_id: nil) }
    scope :for_user, ->(hierarchy, user) { in_hierarchy(hierarchy).where(user_id: user) }
  end
end
