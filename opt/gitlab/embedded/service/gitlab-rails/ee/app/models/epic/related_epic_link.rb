# frozen_string_literal: true

class Epic::RelatedEpicLink < ApplicationRecord
  include IssuableLink
  include CreatedAtFilterable
  include UpdatedAtFilterable

  self.table_name = 'related_epic_links'

  belongs_to :source, class_name: 'Epic'
  belongs_to :target, class_name: 'Epic'
  belongs_to :related_work_item_link, class_name: 'WorkItems::RelatedWorkItemLink',
    foreign_key: :issue_link_id, inverse_of: :related_epic_link

  scope :for_source, ->(item) { where(source_id: item.id) }
  scope :for_target, ->(item) { where(target_id: item.id) }

  scope :with_api_entity_associations, -> do
    preload(
      source: [:sync_object, :author, :labels, { group: [:saml_provider, :route] }],
      target: [:sync_object, :author, :labels, { group: [:saml_provider, :route] }]
    )
  end

  scope :order_by_created_at_asc, -> { order(:created_at) }

  validates :related_work_item_link, presence: true

  class << self
    extend ::Gitlab::Utils::Override

    override :issuable_type
    def issuable_type
      :epic
    end

    def find_or_initialize_from_work_item_link(work_item_link)
      epic_link = find_or_initialize_by(
        source: work_item_link.source.synced_epic,
        target: work_item_link.target.synced_epic
      )

      epic_link.link_type = work_item_link.link_type
      epic_link.issue_link_id = work_item_link.id

      epic_link
    end
  end
end
