# frozen_string_literal: true

module Observability
  class LogsIssuesConnectionPolicy < ::BasePolicy
    delegate { @subject.project }
  end
end
