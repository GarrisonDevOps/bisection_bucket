# frozen_string_literal: true

class GroupHookPolicy < ::BasePolicy
  delegate { @subject.group }
end
