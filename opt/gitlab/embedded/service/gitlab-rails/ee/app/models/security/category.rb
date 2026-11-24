# frozen_string_literal: true

module Security
  class Category < ::SecApplicationRecord
    self.table_name = 'security_categories'
    MAX_ATTRIBUTES = 200
    MAX_CATEGORIES_PER_NAMESPACE = 20

    def self.declarative_policy_class
      'Security::AttributePolicy'
    end

    belongs_to :namespace, optional: false
    has_many :security_attributes, class_name: 'Security::Attribute', inverse_of: :security_category
    has_many :not_deleted_security_attributes, -> { not_deleted }, class_name: 'Security::Attribute',
      foreign_key: :security_category_id, inverse_of: :security_category

    enum :editable_state, Enums::Security.editable_states

    enum :template_type, Enums::Security.categories_template_types

    before_validation :strip_whitespaces
    validates :name, presence: true
    validates :editable_state, presence: true
    validates :multiple_selection, inclusion: { in: [true, false] }
    validates :name, length: { maximum: 255 },
      uniqueness: { scope: :namespace_id, conditions: -> { where(deleted_at: nil) } }
    validates :description, length: { maximum: 255 }, allow_blank: true
    validate :valid_namespace
    validate :attributes_limit

    scope :not_deleted, -> { where(deleted_at: nil) }
    scope :deleted, -> { where.not(deleted_at: nil) }

    scope :by_namespace, ->(namespace) { not_deleted.where(namespace: namespace) }
    scope :by_namespace_and_template_type, ->(namespace, template_type) {
      not_deleted.where(namespace_id: namespace.id, template_type: template_type)
    }
    scope :preload_not_deleted_attributes, -> { preload(:not_deleted_security_attributes) }
    def self.really_destroy_by_id!(category_id)
      return 0 unless category_id

      unscoped.where(id: category_id).delete_all
    end

    def editable?
      editable_state != "locked"
    end

    def destroy
      soft_delete_attributes
      update!(deleted_at: Time.current)
    end

    def deleted?
      deleted_at.present?
    end

    private

    def valid_namespace
      return if namespace&.root? && namespace.group_namespace?

      errors.add(:namespace, 'must be a root group.')
    end

    def attributes_limit
      # For new records, only count the built attributes
      if new_record?
        total_count = security_attributes.not_deleted.size
      else
        # For persisted records, query database directly for accurate count
        existing_count = security_attributes.not_deleted.count
        # Count newly built (unsaved) attributes
        new_attributes_count = security_attributes.count(&:new_record?)
        total_count = existing_count + new_attributes_count
      end

      return unless total_count > MAX_ATTRIBUTES

      errors.add(:security_attributes, "cannot have more than #{MAX_ATTRIBUTES} attributes per category")
    end

    def strip_whitespaces
      self.name = name&.strip
      self.description = description&.strip
    end

    def soft_delete_attributes
      security_attributes.not_deleted.where(security_category_id: id).update_all(deleted_at: Time.current)
    end
  end
end
