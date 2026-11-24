# frozen_string_literal: true

module Cd
  class VersionSetEntryPolicy < ::BasePolicy
    delegate { @subject.version_set }
  end
end
