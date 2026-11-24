# frozen_string_literal: true

class UserAgentDetail < ApplicationRecord
  belongs_to :organization, class_name: 'Organizations::Organization', optional: false
  belongs_to :subject, polymorphic: true # rubocop:disable Cop/PolymorphicAssociations

  validates :user_agent, :ip_address, :subject_id, :subject_type, presence: true

  scope :in_organization, ->(organization) { where(organization: organization) }
  scope :for_subjects, ->(subject_type, subject_ids) { where(subject_type: subject_type, subject_id: subject_ids) }

  def submittable?
    !submitted?
  end
end
