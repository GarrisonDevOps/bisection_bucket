# rubocop:disable Naming/FileName
# frozen_string_literal: true

# LabKit is a module for handling cross-project
# infrastructural concerns, partcularly related to
# observability.
module Labkit
  class << self
    def dev_or_test?
      %w[development test].include?(ENV.fetch("RAILS_ENV", nil))
    end
  end

  autoload :System, "labkit/system"

  autoload :Context, "labkit/context"
  autoload :Correlation, "labkit/correlation"
  autoload :CoveredExperience, "labkit/user_experience_sli" # Backward compatibility alias
  autoload :ApplicationSli, "labkit/application_sli"
  autoload :UserExperienceSli, "labkit/user_experience_sli"
  autoload :FIPS, "labkit/fips"
  autoload :Tracing, "labkit/tracing"
  autoload :Logging, "labkit/logging"
  autoload :Metrics, "labkit/metrics"
  autoload :Middleware, "labkit/middleware"
  autoload :Fields, "labkit/fields"
  autoload :RateLimit, "labkit/rate_limit"
  autoload :Redis, "labkit/redis"

  # Publishers to publish notifications whenever a HTTP reqeust is made.
  # A broadcasted notification's payload in topic "request.external_http" includes:
  #   + method (String): "GET"
  #   + code (String): "200" # This is the status code read directly from HTTP response
  #   + duration (Float - seconds): 0.234
  #   + host (String): "gitlab.com"
  #   + port (Integer): 80,
  #   + path (String): "/gitlab-org/gitlab"
  #   + scheme (String): "https"
  #   + query (String): "field_a=1&field_b=2"
  #   + fragment (String): "issue-number-1"
  #   + proxy_host (String - Optional): "proxy.gitlab.com"
  #   + proxy_port (Integer - Optional): 80
  #   + exception (Array<String> - Optional): ["Net::ReadTimeout", "Net::ReadTimeout with #<TCPSocket:(closed)>"]
  #   + exception_object (Error Object - Optional): #<Net::ReadTimeout: Net::ReadTimeout>
  #
  # Usage:
  #
  # ActiveSupport::Notifications.subscribe "request.external_http" do |name, started, finished, unique_id, data|
  #   puts "#{name} | #{started} | #{finished} | #{unique_id} | #{data.inspect}"
  # end
  #
  EXTERNAL_HTTP_NOTIFICATION_TOPIC = "request.external_http"
  autoload :NetHttpPublisher, "labkit/net_http_publisher"
  autoload :ExconPublisher, "labkit/excon_publisher"
  autoload :HTTPClientPublisher, "labkit/httpclient_publisher"
end

Labkit::Tracing::AutoInitialize.initialize! if defined?(Labkit::Tracing)

# rubocop:enable Naming/FileName
