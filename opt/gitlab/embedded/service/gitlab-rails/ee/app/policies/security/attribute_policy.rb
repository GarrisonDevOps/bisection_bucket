# frozen_string_literal: true

module Security
  class AttributePolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
