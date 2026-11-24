# frozen_string_literal: true

module Dast
  class ProfileTag < ::SecApplicationRecord
    MAX_NAME_LENGTH = 255

    self.table_name = 'dast_profiles_tags'

    belongs_to :tag, class_name: 'Ci::Tag', optional: false
    belongs_to :dast_profile, class_name: 'Dast::Profile', optional: false

    before_validation :copy_tag_name_from_tags, if: -> { tag_name.nil? && tag.present? }

    validates :tag_name, presence: true, length: { maximum: MAX_NAME_LENGTH }

    private

    def copy_tag_name_from_tags
      self.tag_name = tag.name
    end
  end
end
