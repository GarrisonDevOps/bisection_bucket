# frozen_string_literal: true

module Ci
  module Catalog
    class ResourcePolicy < BasePolicy
      delegate { @subject.project }
    end
  end
end
