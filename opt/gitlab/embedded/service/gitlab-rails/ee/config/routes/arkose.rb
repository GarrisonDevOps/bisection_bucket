# frozen_string_literal: true

scope 'arkose', module: 'anti_abuse' do
  get 'data_exchange_payload', controller: 'arkose', action: :data_exchange_payload
end
