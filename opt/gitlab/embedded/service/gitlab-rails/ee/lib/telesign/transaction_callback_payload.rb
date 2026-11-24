# frozen_string_literal: true

#
# https://developer.telesign.com/enterprise/docs/transaction-callback-service#schema
#
module Telesign
  class TransactionCallbackPayload
    attr_reader :payload

    def initialize(json)
      @payload = json
    end

    def reference_id
      payload['reference_id']
    end

    def status
      description = payload.dig('status', 'description')
      [status_code, description].compact.join(' - ')
    end

    def status_updated_on
      payload.dig('status', 'updated_on')
    end

    def errors
      return '' unless payload['errors'].is_a?(Array)

      payload['errors'].map do |error|
        [error['code'], error['description']].compact.join(' - ')
      end.join(', ')
    end

    def failed_delivery?
      status_code != 200
    end

    def country_blocked?
      # https://developer.telesign.com/enterprise/docs/all-status-and-error-codes#status-codes
      # 237	- Message blocked in requested country
      status_code == 237
    end

    private

    def status_code
      @status_code ||= payload.dig('status', 'code')
    end
  end
end
