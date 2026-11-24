# frozen_string_literal: true

class LDAPKey < Key
  include UsageStatistics

  self.allow_legacy_sti_class = true

  def can_delete?
    false
  end
end
