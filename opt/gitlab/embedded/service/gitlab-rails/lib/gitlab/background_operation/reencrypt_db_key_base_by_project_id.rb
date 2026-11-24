# frozen_string_literal: true

module Gitlab
  module BackgroundOperation
    # {ReencryptDbKeyBase} for the tables keyed on `project_id`, such as `project_settings`
    class ReencryptDbKeyBaseByProjectId < ReencryptDbKeyBase
      cursor :project_id
    end
  end
end
