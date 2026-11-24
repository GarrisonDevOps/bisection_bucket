# frozen_string_literal: true

class EpicUserMention < UserMention
  belongs_to :epic
  belongs_to :note
  belongs_to :group
end
