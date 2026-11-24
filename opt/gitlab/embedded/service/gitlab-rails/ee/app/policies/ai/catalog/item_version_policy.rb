# frozen_string_literal: true

module Ai
  module Catalog
    class ItemVersionPolicy < ::BasePolicy
      delegate { @subject.item }
    end
  end
end
