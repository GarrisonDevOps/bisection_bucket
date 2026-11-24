# frozen_string_literal: true

module Security
  class Attribute < ::SecApplicationRecord
    include StripAttribute

    self.table_name = 'security_attributes'

    belongs_to :namespace, optional: false
    belongs_to :security_category, class_name: 'Security::Category', optional: false
    has_many :project_to_security_attributes, class_name: 'Security::ProjectToSecurityAttribute',
      foreign_key: :security_attribute_id, inverse_of: :security_attribute
    has_many :projects, through: :project_to_security_attributes

    strip_attributes! :name, :description

    enum :editable_state, Enums::Security.editable_states
    enum :template_type, Enums::Security.attributes_template_types
    attribute :color, ::Gitlab::Database::Type::Color.new

    validates :name, presence: true, length: { maximum: 255 },
      uniqueness: { scope: :security_category_id, conditions: -> { where(deleted_at: nil) } }
    validates :description, presence: true, length: { maximum: 255 }
    validates :editable_state, presence: true
    validates :color, color: true, presence: true

    scope :not_deleted, -> { where(deleted_at: nil) }
    scope :deleted, -> { where.not(deleted_at: nil) }

    scope :include_category, -> { includes(:security_category) }
    scope :by_category, ->(category) { where(security_category: category) }
    scope :by_namespace, ->(namespace) { where(namespace: namespace) }
    scope :by_template_type, ->(template_type) { where(template_type: template_type) }
    scope :by_category_template_type, ->(template_type) {
      return none if template_type.blank?

      not_deleted.joins(:security_category)
                 .merge(Security::Category.not_deleted)
                 .where(security_categories: { template_type: template_type })
    }
    scope :pluck_id, -> { limit(MAX_PLUCK).pluck(:id) }
    scope :pluck_category_template_type_id, -> {
      joins(:security_category).limit(MAX_PLUCK).pluck('security_categories.template_type', :id)
    }
    scope :not_deleted_with_not_deleted_categories, -> { not_deleted.joins(:security_category).merge(Security::Category.not_deleted) }

    def self.really_destroy_all!(ids)
      return 0 if ids.blank?

      unscoped.where(id: ids).delete_all
    end

    def editable?
      !locked?
    end

    def destroy
      update!(deleted_at: Time.current)
    end

    def deleted?
      deleted_at.present?
    end
  end
end
