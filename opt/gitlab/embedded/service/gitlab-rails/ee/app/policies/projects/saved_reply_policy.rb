# frozen_string_literal: true

module Projects
  class SavedReplyPolicy < BasePolicy
    delegate { @subject.project }
  end
end
