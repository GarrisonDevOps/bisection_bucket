# frozen_string_literal: true

module AuditEvents
  module Streaming
    module InstanceHeaders
      class CreateService < BaseService
        def execute
          create_header(params[:destination], params[:key], params[:value], params[:active])
        end
      end
    end
  end
end
