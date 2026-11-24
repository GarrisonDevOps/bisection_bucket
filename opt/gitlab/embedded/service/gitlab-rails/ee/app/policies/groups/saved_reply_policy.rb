# frozen_string_literal: true

module Groups
  class SavedReplyPolicy < BasePolicy
    delegate { @subject.group }
  end
end
