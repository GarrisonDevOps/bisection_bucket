# frozen_string_literal: true

class SystemHookPolicy < ::BasePolicy
  delegate { @subject.organization }
end
