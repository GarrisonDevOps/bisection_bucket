# frozen_string_literal: true

module IncidentManagement
  class IssuableResourceLink < ApplicationRecord
    self.table_name = 'issuable_resource_links'
    attribute :is_unique, default: true # TODO: to remove after https://gitlab.com/gitlab-org/gitlab/-/issues/437902

    belongs_to :issue, inverse_of: :issuable_resource_links
    has_one :project, through: :issue

    enum :link_type, { general: 0, zoom: 1, slack: 2, pagerduty: 3 } # 'general' is the default type

    validates :issue, presence: true
    validates :link,
      presence: true,
      length: { maximum: 2200 },
      addressable_url: { schemes: %w[http https] },
      uniqueness: {
        scope: :issue_id,
        case_sensitive: false,
        message: 'already exists for this incident'
      }
    validates :link_text, length: { maximum: 255 }

    scope :order_by_created_at_asc, -> { reorder(created_at: :asc) }
    scope :slack_links, -> { where(link_type: :slack) }
    scope :zoom_links, -> { where(link_type: :zoom) }
    scope :pagerduty_links, -> { where(link_type: :pagerduty) }
  end
end
