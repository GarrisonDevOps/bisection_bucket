# frozen_string_literal: true

module Observability
  class MetricsIssuesConnectionPolicy < ::BasePolicy
    delegate { @subject.project }
  end
end
