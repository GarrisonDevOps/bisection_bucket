# frozen_string_literal: true

module GitlabSubscriptions
  class UserAddOnAssignment < ApplicationRecord
    has_paper_trail(
      versions: {
        class_name: 'GitlabSubscriptions::UserAddOnAssignmentVersion'
      },
      meta: {
        organization_id: :add_on_purchase_organization_id,
        namespace_path: :namespace_traversal_path,
        user_id: :user_id,
        add_on_name: :add_on_name,
        purchase_id: :add_on_purchase_id
      }
    )

    belongs_to :user, inverse_of: :assigned_add_ons
    belongs_to :add_on_purchase, class_name: 'GitlabSubscriptions::AddOnPurchase', inverse_of: :assigned_users
    belongs_to :organization, class_name: 'Organizations::Organization', inverse_of: :user_add_on_assignments

    validates :user, :add_on_purchase, presence: true
    validates :add_on_purchase_id, uniqueness: { scope: :user_id }

    scope :by_user, ->(user) { where(user: user) }
    scope :for_user_ids, ->(user_ids) { where(user_id: user_ids) }
    scope :with_namespaces, -> { includes(add_on_purchase: :namespace) }
    scope :for_add_on_purchases, ->(add_on_purchases) { where(add_on_purchase: add_on_purchases) }
    scope :for_active_add_on_purchases, ->(add_on_purchases) do
      joins(:add_on_purchase).merge(add_on_purchases.active)
    end

    scope :for_active_gitlab_duo_purchase, -> do
      for_active_add_on_purchases(::GitlabSubscriptions::AddOnPurchase.for_duo_add_ons)
    end

    scope :for_active_add_on_purchase_ids, ->(add_on_purchase_ids) do
      for_active_add_on_purchases(::GitlabSubscriptions::AddOnPurchase.where(id: add_on_purchase_ids))
    end

    scope :order_by_id_desc, -> { order(id: :desc) }

    delegate :namespace, :namespace_id, to: :add_on_purchase

    def self.pluck_user_ids
      pluck(:user_id)
    end

    def namespace_traversal_path
      add_on_purchase.namespace&.traversal_path(with_organization: false)
    end

    # Get organization_id from add_on_purchase association for paper trail versioning record.
    #
    # We cannot rely on this model because its organization_id
    # is set using a database before INSERT trigger, at the
    # time paper trail version record is created this model is dirty with
    # organization_id as nil.
    def add_on_purchase_organization_id
      add_on_purchase.organization_id
    end

    def add_on_name
      add_on_purchase.add_on.name
    end
  end
end
