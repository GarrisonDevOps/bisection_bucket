# frozen_string_literal: true

module Gitlab
  module BackgroundOperation
    # {ReencryptDbKeyBase} for the tables keyed on `user_id`, such as `atlassian_identities`
    class ReencryptDbKeyBaseByUserId < ReencryptDbKeyBase
      cursor :user_id
    end
  end
end
