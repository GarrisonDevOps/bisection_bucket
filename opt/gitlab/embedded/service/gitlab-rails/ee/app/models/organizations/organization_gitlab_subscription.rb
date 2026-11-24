# frozen_string_literal: true

module Organizations
  class OrganizationGitlabSubscription < ApplicationRecord
    belongs_to :organization, class_name: 'Organizations::Organization', optional: false,
      inverse_of: :organization_gitlab_subscription
    belongs_to :gitlab_subscription, optional: false, inverse_of: :organization_gitlab_subscription

    validates :organization, uniqueness: true
    validates :gitlab_subscription, uniqueness: true
    validate :organization_is_not_default, if: :organization

    private

    # Default Organization groups keep resolving their own subscription.
    def organization_is_not_default
      return unless organization.default?

      errors.add(:organization, "can't be the default organization")
    end
  end
end
