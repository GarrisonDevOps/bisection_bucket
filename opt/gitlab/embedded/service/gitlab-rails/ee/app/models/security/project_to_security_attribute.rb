# frozen_string_literal: true

module Security
  class ProjectToSecurityAttribute < ::SecApplicationRecord
    self.table_name = 'project_to_security_attributes'

    include ::Namespaces::Traversal::Traversable
    include BulkInsertSafe

    belongs_to :project, optional: false, inverse_of: :project_to_security_attributes
    belongs_to :security_attribute, class_name: 'Security::Attribute', optional: false,
      inverse_of: :project_to_security_attributes

    validates :traversal_ids, presence: true
    validates :security_attribute_id, uniqueness: { scope: :project_id }
    validate :same_root_ancestor

    scope :by_attribute_id, ->(attribute_id) { where(security_attribute_id: attribute_id) }
    scope :by_project_id, ->(project_id) { where(project_id: project_id) }
    scope :id_after, ->(id) { where(arel_table[:id].gt(id)) }
    scope :order_by_project_and_id, ->(direction = :asc) { order(project_id: direction, id: direction) }
    scope :excluding_root_namespace, ->(root_namespace_id) {
      where(sanitize_sql_array(["traversal_ids[1] != ?", root_namespace_id]))
    }
    scope :by_security_attributes, ->(is_one_of_filters, is_not_one_of_filters) do
      return none if is_one_of_filters.empty? && is_not_one_of_filters.empty?

      scope = all

      is_one_of_filters.each do |attribute_ids|
        scope = scope.where(
          "EXISTS (
            SELECT 1 FROM project_to_security_attributes exists_ptsa
            WHERE exists_ptsa.project_id = project_to_security_attributes.project_id
            AND exists_ptsa.security_attribute_id IN (?)
          )", attribute_ids
        )
      end

      if is_not_one_of_filters.any?
        all_excluded = is_not_one_of_filters.flatten.uniq
        scope = scope.where(
          "NOT EXISTS (
            SELECT 1 FROM project_to_security_attributes not_exists_ptsa
            WHERE not_exists_ptsa.project_id = project_to_security_attributes.project_id
            AND not_exists_ptsa.security_attribute_id IN (?)
          )", all_excluded
        )
      end

      scope
    end

    def self.pluck_id(limit = MAX_PLUCK)
      limit(limit).pluck(:id)
    end

    private

    def same_root_ancestor
      return unless project&.namespace && security_attribute&.namespace
      return if project.namespace.root_ancestor == security_attribute.namespace

      errors.add(:base, 'Project and attribute must belong to the same namespace')
    end
  end
end
