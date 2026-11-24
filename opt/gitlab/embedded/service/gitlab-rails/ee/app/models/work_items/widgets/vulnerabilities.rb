# frozen_string_literal: true

module WorkItems
  module Widgets
    class Vulnerabilities < Base
      delegate :related_vulnerabilities, to: :work_item
    end
  end
end
