# frozen_string_literal: true

module Observability
  class TracesIssuesConnectionPolicy < ::BasePolicy
    delegate { @subject.project }
  end
end
